"""Parse ``terraform show -json`` output into changes and a dependency graph.

Terraform tells you *what* it will change. It does not tell you what that change
can reach. This module recovers the second half from the plan's ``configuration``
block, which records the references every resource expression makes — the same
edges Terraform itself uses to order the apply.

Two things worth knowing about the format:

* An action is a *list*. A replace is ``["delete", "create"]``, not a
  ``"replace"`` action, and treating it as a create is how a destroyed database
  gets reviewed as a harmless addition.
* References come back doubled: ``aws_security_group.db.id`` alongside
  ``aws_security_group.db``. Both must be normalised to the resource address or
  the graph counts every edge twice.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .errors import PlanError

#: Plan format versions this parser has been checked against. A newer one is a
#: warning rather than a hard failure — the fields we read are stable — but an
#: older major version means a different schema entirely.
SUPPORTED_FORMAT_MAJOR = {"0", "1"}


class Action(StrEnum):
    """What Terraform intends to do to one resource."""

    NOOP = "no-op"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"
    READ = "read"

    @property
    def destroys_data(self) -> bool:
        """True when the existing object stops existing.

        This is the property that matters. A replace is not an update: the old
        object is destroyed, and anything living inside it — rows, objects,
        volumes — goes with it.
        """
        return self in (Action.DELETE, Action.REPLACE)


def parse_actions(actions: Any) -> Action:
    """Collapse Terraform's action list into a single verdict."""
    if not isinstance(actions, list) or not actions:
        raise PlanError(f"malformed change actions: {actions!r}")

    cleaned = [str(a) for a in actions]
    if cleaned == ["no-op"]:
        return Action.NOOP
    if cleaned == ["create"]:
        return Action.CREATE
    if cleaned == ["update"]:
        return Action.UPDATE
    if cleaned == ["delete"]:
        return Action.DELETE
    if cleaned == ["read"]:
        return Action.READ
    # Both orderings appear depending on create_before_destroy.
    if set(cleaned) == {"delete", "create"}:
        return Action.REPLACE
    raise PlanError(f"unrecognised action combination: {cleaned}")


def normalise_reference(reference: str) -> str | None:
    """Reduce a configuration reference to a resource address.

    ``aws_security_group.db.id`` and ``aws_security_group.db`` both become
    ``aws_security_group.db``. References to variables, locals, data sources and
    ``each``/``count`` are dropped — they are not nodes we can reason about.
    """
    text = reference.strip()
    if not text:
        return None

    parts = text.split(".")
    head = parts[0]
    if head in {"var", "local", "each", "count", "path", "terraform", "self"}:
        return None
    if head == "data":
        # data.aws_ami.ubuntu[.id] -> data.aws_ami.ubuntu
        return ".".join(parts[:3]) if len(parts) >= 3 else None
    if head == "module":
        # module.network.vpc_id -> module.network
        return ".".join(parts[:2]) if len(parts) >= 2 else None
    if len(parts) < 2:
        return None
    # aws_instance.web[.attr...] -> aws_instance.web
    return f"{parts[0]}.{parts[1]}"


def qualify(address: str, module_address: str | None) -> str:
    """Prefix a module-local address with its module path."""
    if not module_address:
        return address
    return f"{module_address}.{address}"


@dataclass(frozen=True, slots=True)
class ResourceChange:
    """One planned change."""

    address: str
    type: str
    name: str
    action: Action
    module_address: str = ""
    provider: str = ""
    action_reason: str = ""
    replace_paths: tuple[str, ...] = ()
    changed_attributes: tuple[str, ...] = ()

    @property
    def is_managed_change(self) -> bool:
        """Data-source reads and no-ops are not changes anyone needs to review."""
        return self.action not in (Action.NOOP, Action.READ)

    @property
    def why_replaced(self) -> str:
        """A human explanation of a forced replacement, when Terraform gave one."""
        if self.action is not Action.REPLACE:
            return ""
        if self.replace_paths:
            return f"forced by change to {', '.join(self.replace_paths)}"
        return self.action_reason.replace("_", " ") if self.action_reason else "forced replacement"


@dataclass
class Plan:
    """A parsed plan: the changes, plus the graph they sit in."""

    changes: tuple[ResourceChange, ...]
    #: address -> addresses it references (its dependencies)
    dependencies: dict[str, set[str]] = field(default_factory=dict)
    terraform_version: str = ""
    format_version: str = ""

    @property
    def actionable(self) -> tuple[ResourceChange, ...]:
        return tuple(c for c in self.changes if c.is_managed_change)

    def count(self, action: Action) -> int:
        return sum(1 for c in self.changes if c.action is action)

    @property
    def dependents(self) -> dict[str, set[str]]:
        """Inverted graph: address -> addresses that depend on it.

        This is the direction that matters for blast radius. "What does this
        resource need?" is a question about apply ordering; "what needs this
        resource?" is a question about who breaks when it goes away.
        """
        inverted: dict[str, set[str]] = {}
        for source, targets in self.dependencies.items():
            for target in targets:
                inverted.setdefault(target, set()).add(source)
        return inverted

    def transitive_dependents(self, address: str) -> set[str]:
        """Everything that would be affected, directly or indirectly.

        Iterative rather than recursive, and cycle-safe via the visited set —
        Terraform rejects true cycles, but module-boundary approximation can
        introduce them, and a stack overflow is a poor way to report that.
        """
        dependents = self.dependents
        seen: set[str] = set()
        queue = list(dependents.get(address, ()))
        while queue:
            current = queue.pop()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(dependents.get(current, ()))
        seen.discard(address)
        return seen


def _walk_module(
    module: dict[str, Any], module_address: str, dependencies: dict[str, set[str]]
) -> None:
    """Collect reference edges from one configuration module, then recurse.

    References inside a module are module-local, so they are qualified with the
    current module path. Cross-module references travel through variables and
    outputs, which the plan does not expose as resource-to-resource edges — those
    are approximated by an edge to the module call itself.
    """
    for resource in module.get("resources", []) or []:
        if not isinstance(resource, dict):
            continue
        address = qualify(str(resource.get("address", "")), module_address)
        if not address:
            continue

        targets: set[str] = dependencies.setdefault(address, set())

        for expression in (resource.get("expressions") or {}).values():
            for reference in _references_in(expression):
                resolved = normalise_reference(reference)
                if resolved and resolved != str(resource.get("address", "")):
                    targets.add(qualify(resolved, module_address))

        for reference in resource.get("depends_on", []) or []:
            resolved = normalise_reference(str(reference))
            if resolved:
                targets.add(qualify(resolved, module_address))

        targets.discard(address)

    for name, call in (module.get("module_calls") or {}).items():
        if not isinstance(call, dict):
            continue
        child_address = qualify(f"module.{name}", module_address)
        child = call.get("module")
        if isinstance(child, dict):
            _walk_module(child, child_address, dependencies)


def _references_in(expression: Any) -> list[str]:
    """Pull every ``references`` list out of a (possibly nested) expression node."""
    found: list[str] = []
    if isinstance(expression, dict):
        raw = expression.get("references")
        if isinstance(raw, list):
            found.extend(str(r) for r in raw)
        for value in expression.values():
            if isinstance(value, (dict, list)):
                found.extend(_references_in(value))
    elif isinstance(expression, list):
        for item in expression:
            found.extend(_references_in(item))
    return found


def _changed_attributes(change: dict[str, Any]) -> tuple[str, ...]:
    """Top-level attributes whose value differs between before and after.

    Only top level: a deep diff would be noise in a risk summary, and the
    attributes that force replacement are surfaced separately by Terraform.
    """
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return ()
    keys = sorted(set(before) | set(after))
    return tuple(k for k in keys if before.get(k) != after.get(k))


def _replace_paths(change: dict[str, Any]) -> tuple[str, ...]:
    """Flatten ``replace_paths`` (a list of attribute paths) into readable names."""
    paths = change.get("replace_paths")
    if not isinstance(paths, list):
        return ()
    rendered: list[str] = []
    for path in paths:
        if isinstance(path, list):
            rendered.append(".".join(str(p) for p in path))
        elif path is not None:
            rendered.append(str(path))
    return tuple(rendered)


def parse_plan(payload: Any) -> Plan:
    """Build a :class:`Plan` from decoded ``terraform show -json`` output."""
    if not isinstance(payload, dict):
        raise PlanError(f"plan must be a JSON object, got {type(payload).__name__}")

    format_version = str(payload.get("format_version", ""))
    if format_version:
        major = format_version.split(".")[0]
        if major not in SUPPORTED_FORMAT_MAJOR:
            raise PlanError(
                f"unsupported plan format_version {format_version!r}. "
                f"This parser understands major versions {sorted(SUPPORTED_FORMAT_MAJOR)}."
            )

    raw_changes = payload.get("resource_changes")
    if raw_changes is None:
        raise PlanError(
            "plan has no 'resource_changes'. Generate it with "
            "`terraform plan -out=tfplan && terraform show -json tfplan`, not `terraform plan -json`."
        )
    if not isinstance(raw_changes, list):
        raise PlanError("'resource_changes' must be a list")

    changes: list[ResourceChange] = []
    for entry in raw_changes:
        if not isinstance(entry, dict):
            raise PlanError(f"malformed resource_change entry: {entry!r}")
        change = entry.get("change")
        if not isinstance(change, dict):
            raise PlanError(f"resource_change {entry.get('address')!r} has no change block")

        changes.append(
            ResourceChange(
                address=str(entry.get("address", "")),
                type=str(entry.get("type", "")),
                name=str(entry.get("name", "")),
                action=parse_actions(change.get("actions")),
                module_address=str(entry.get("module_address", "")),
                provider=str(entry.get("provider_name", "")),
                action_reason=str(entry.get("action_reason", "")),
                replace_paths=_replace_paths(change),
                changed_attributes=_changed_attributes(change),
            )
        )

    dependencies: dict[str, set[str]] = {}
    configuration = payload.get("configuration")
    if isinstance(configuration, dict):
        root = configuration.get("root_module")
        if isinstance(root, dict):
            _walk_module(root, "", dependencies)

    return Plan(
        changes=tuple(changes),
        dependencies=dependencies,
        terraform_version=str(payload.get("terraform_version", "")),
        format_version=format_version,
    )


def load_plan(path: str | Path) -> Plan:
    """Read and parse a plan JSON file."""
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PlanError(f"cannot read plan {target}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PlanError(
            f"plan {target} is not valid JSON: {exc}. "
            f"Did you pipe `terraform plan` output instead of `terraform show -json`?"
        ) from exc
    return parse_plan(payload)
