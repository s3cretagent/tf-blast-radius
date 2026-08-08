"""Policy: turning a risk score into a decision.

A number on its own changes nothing - somebody still merges the PR. Policy is
where the score acquires teeth: block the apply, or demand more eyes on it.

Rules are evaluated in order and the first match wins, so a specific carve-out
can sit above a broad rule without needing exception logic.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from .errors import PolicyError
from .plan import Action
from .score import Assessment, Finding

_RULE_KEYS = frozenset(
    {"name", "match", "action", "message", "min_score", "max_score", "actions", "categories"}
)
_MATCH_KEYS = frozenset({"address", "type", "category", "action", "min_score", "min_dependents"})
_TOP_KEYS = frozenset({"version", "thresholds", "rules"})
_THRESHOLD_KEYS = frozenset({"block_above", "review_above", "required_approvals"})


class Outcome(StrEnum):
    """What the gate decided."""

    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"

    @property
    def blocks(self) -> bool:
        return self is Outcome.BLOCK


@dataclass(frozen=True, slots=True)
class Rule:
    """One policy rule. ``match`` is a conjunction - every stated field must hold."""

    name: str
    outcome: Outcome
    message: str = ""
    address: str = ""
    type: str = ""
    category: str = ""
    action: str = ""
    min_score: int = 0
    min_dependents: int = 0

    def matches(self, finding: Finding) -> bool:
        if self.address and not fnmatch.fnmatch(finding.address, self.address):
            return False
        if self.type and not fnmatch.fnmatch(finding.change.type, self.type):
            return False
        if self.category and finding.category != self.category:
            return False
        if self.action and finding.change.action.value != self.action:
            return False
        if finding.score < self.min_score:
            return False
        return finding.transitive_dependents >= self.min_dependents


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Score bands used when no rule matches."""

    block_above: int = 80
    review_above: int = 50
    required_approvals: int = 2

    def outcome_for(self, score: int) -> Outcome:
        if score > self.block_above:
            return Outcome.BLOCK
        if score > self.review_above:
            return Outcome.REVIEW
        return Outcome.ALLOW


@dataclass(frozen=True, slots=True)
class Policy:
    """A set of rules plus fallback thresholds."""

    rules: tuple[Rule, ...] = ()
    thresholds: Thresholds = field(default_factory=Thresholds)
    source: str = "<default>"


@dataclass(frozen=True, slots=True)
class Violation:
    """A rule that fired against a specific finding."""

    finding: Finding
    rule: Rule

    @property
    def message(self) -> str:
        return self.rule.message or f"matched policy rule {self.rule.name!r}"


@dataclass(frozen=True, slots=True)
class Verdict:
    """The gate's decision for a whole plan."""

    outcome: Outcome
    assessment: Assessment
    violations: tuple[Violation, ...] = ()
    required_approvals: int = 0
    reason: str = ""

    @property
    def blocked(self) -> tuple[Violation, ...]:
        return tuple(v for v in self.violations if v.rule.outcome is Outcome.BLOCK)


DEFAULT_POLICY = Policy(
    rules=(
        Rule(
            name="stateful-destroy",
            outcome=Outcome.BLOCK,
            category="stateful",
            action="delete",
            message=(
                "destroying a stateful resource loses data that no re-apply brings back. "
                "If this is intentional, take a verified backup and record it on the PR."
            ),
        ),
        Rule(
            name="stateful-replace",
            outcome=Outcome.BLOCK,
            category="stateful",
            action="replace",
            message=(
                "an in-place replacement destroys the existing object first. For databases "
                "and volumes this is a data-loss event wearing an update's clothing."
            ),
        ),
        Rule(
            name="wide-blast-radius",
            outcome=Outcome.REVIEW,
            min_dependents=10,
            message="more than ten resources depend on this one; the failure surface is wide",
        ),
        Rule(
            name="guardrail-removal",
            outcome=Outcome.REVIEW,
            category="guardrail",
            action="delete",
            message=(
                "removing a security control breaks nothing today, so nothing will alert. "
                "Confirm the control has been replaced, not simply dropped."
            ),
        ),
    ),
)


def _reject_unknown(got: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = set(got) - allowed
    if unknown:
        raise PolicyError(
            f"{where}: unknown key(s) {', '.join(sorted(unknown))}; "
            f"allowed: {', '.join(sorted(allowed))}"
        )


def _parse_rule(raw: Any, index: int) -> Rule:
    where = f"rules[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: expected a mapping")
    _reject_unknown(raw, _RULE_KEYS, where)

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PolicyError(f"{where}.name: required")
    where = f"rule {name!r}"

    outcome_raw = str(raw.get("action", "")).lower()
    try:
        outcome = Outcome(outcome_raw)
    except ValueError:
        valid = ", ".join(o.value for o in Outcome)
        raise PolicyError(f"{where}.action: expected one of {valid}, got {outcome_raw!r}") from None

    match = raw.get("match") or {}
    if not isinstance(match, dict):
        raise PolicyError(f"{where}.match: expected a mapping")
    _reject_unknown(match, _MATCH_KEYS, f"{where}.match")

    action_filter = str(match.get("action", ""))
    if action_filter and action_filter not in {a.value for a in Action}:
        valid = ", ".join(a.value for a in Action)
        raise PolicyError(f"{where}.match.action: expected one of {valid}, got {action_filter!r}")

    category = str(match.get("category", ""))
    if category and category not in {"stateful", "serving", "guardrail", "stateless"}:
        raise PolicyError(
            f"{where}.match.category: expected stateful, serving, guardrail or stateless, "
            f"got {category!r}"
        )

    return Rule(
        name=name.strip(),
        outcome=outcome,
        message=str(raw.get("message", "")).strip(),
        address=str(match.get("address", "")),
        type=str(match.get("type", "")),
        category=category,
        action=action_filter,
        min_score=int(match.get("min_score", 0)),
        min_dependents=int(match.get("min_dependents", 0)),
    )


def load_policy(path: str | Path) -> Policy:
    """Parse a policy file."""
    target = Path(path)
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"cannot read policy: {exc}", source=str(target)) from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML: {exc}", source=str(target)) from exc

    source = str(target)
    if not isinstance(raw, dict) or not raw:
        raise PolicyError("policy is empty", source=source)
    _reject_unknown(raw, _TOP_KEYS, "document")

    version = raw.get("version", 1)
    if version != 1:
        raise PolicyError(f"unsupported version {version!r}", source=source)

    thresholds_raw = raw.get("thresholds") or {}
    if not isinstance(thresholds_raw, dict):
        raise PolicyError("'thresholds' must be a mapping", source=source)
    _reject_unknown(thresholds_raw, _THRESHOLD_KEYS, "thresholds")

    thresholds = Thresholds(
        block_above=int(thresholds_raw.get("block_above", 80)),
        review_above=int(thresholds_raw.get("review_above", 50)),
        required_approvals=int(thresholds_raw.get("required_approvals", 2)),
    )
    if thresholds.review_above > thresholds.block_above:
        raise PolicyError(
            f"thresholds: review_above ({thresholds.review_above}) is higher than block_above "
            f"({thresholds.block_above}), so nothing could ever land in the review band",
            source=source,
        )

    rules_raw = raw.get("rules") or []
    if not isinstance(rules_raw, list):
        raise PolicyError("'rules' must be a list", source=source)

    try:
        rules = tuple(_parse_rule(entry, i) for i, entry in enumerate(rules_raw))
    except PolicyError as exc:
        raise PolicyError(str(exc), source=source) from exc

    return Policy(rules=rules, thresholds=thresholds, source=source)


def evaluate(assessment: Assessment, policy: Policy | None = None) -> Verdict:
    """Apply policy to a scored plan.

    Each finding is matched against the rules in order, first match winning, so
    a specific carve-out placed above a broad rule works without exception
    logic. Findings that match nothing fall back to the score thresholds.
    """
    policy = policy or DEFAULT_POLICY
    violations: list[Violation] = []
    outcome = Outcome.ALLOW

    for finding in assessment.ranked:
        matched: Rule | None = next((r for r in policy.rules if r.matches(finding)), None)
        if matched is not None:
            violations.append(Violation(finding=finding, rule=matched))
            finding_outcome = matched.outcome
        else:
            finding_outcome = policy.thresholds.outcome_for(finding.score)

        if finding_outcome is Outcome.BLOCK:
            outcome = Outcome.BLOCK
        elif finding_outcome is Outcome.REVIEW and outcome is not Outcome.BLOCK:
            outcome = Outcome.REVIEW

    # The aggregate score can trip the gate even when no single change did - a
    # plan of many individually-tolerable destructive changes is still a bad day.
    aggregate = policy.thresholds.outcome_for(assessment.score)
    if aggregate is Outcome.BLOCK:
        outcome = Outcome.BLOCK
    elif aggregate is Outcome.REVIEW and outcome is Outcome.ALLOW:
        outcome = Outcome.REVIEW

    approvals = policy.thresholds.required_approvals if outcome is not Outcome.ALLOW else 0
    return Verdict(
        outcome=outcome,
        assessment=assessment,
        violations=tuple(violations),
        required_approvals=approvals,
        reason=_reason(outcome, assessment, violations, policy),
    )


def _reason(
    outcome: Outcome, assessment: Assessment, violations: list[Violation], policy: Policy
) -> str:
    if outcome is Outcome.ALLOW:
        return f"blast radius {assessment.score}/100 - within policy"

    blocking = [v for v in violations if v.rule.outcome is Outcome.BLOCK]
    if blocking:
        names = ", ".join(sorted({v.rule.name for v in blocking}))
        return (
            f"blast radius {assessment.score}/100 - blocked by {len(blocking)} finding(s) "
            f"under rule(s): {names}"
        )
    if outcome is Outcome.BLOCK:
        return (
            f"blast radius {assessment.score}/100 exceeds the block threshold "
            f"({policy.thresholds.block_above})"
        )
    return (
        f"blast radius {assessment.score}/100 - requires "
        f"{policy.thresholds.required_approvals} approvals"
    )
