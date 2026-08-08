"""Report rendering.

The markdown renderer is the important one — it is what a reviewer sees on the
pull request, and it leads with the verdict rather than the inventory. A wall of
resource addresses is what `terraform plan` already gives you; the value added
here is the sentence at the top telling you whether to worry.
"""

from __future__ import annotations

import json
import os
import sys

from .plan import Action
from .policy import Outcome, Verdict
from .score import Finding

_OUTCOME_ICON = {Outcome.ALLOW: "🟢", Outcome.REVIEW: "🟡", Outcome.BLOCK: "🔴"}
_OUTCOME_LABEL = {
    Outcome.ALLOW: "LOW RISK",
    Outcome.REVIEW: "NEEDS REVIEW",
    Outcome.BLOCK: "BLOCKED",
}
_ANSI = {Outcome.ALLOW: "\033[32m", Outcome.REVIEW: "\033[33m", Outcome.BLOCK: "\033[31m"}
_ACTION_ICON = {
    Action.CREATE: "+",
    Action.UPDATE: "~",
    Action.DELETE: "-",
    Action.REPLACE: "±",
    Action.READ: "<",
    Action.NOOP: " ",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def use_colour(stream: object = None) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        return False
    target = stream if stream is not None else sys.stdout
    isatty = getattr(target, "isatty", None)
    return bool(isatty and isatty())


def _bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def _counts(verdict: Verdict) -> str:
    assessment = verdict.assessment
    return (
        f"{assessment.count(Action.CREATE)} to add, "
        f"{assessment.count(Action.UPDATE)} to change, "
        f"{assessment.count(Action.REPLACE)} to replace, "
        f"{assessment.count(Action.DELETE)} to destroy"
    )


def render_text(verdict: Verdict, *, colour: bool | None = None) -> str:
    if colour is None:
        colour = use_colour()

    assessment = verdict.assessment
    headline = (
        f"BLAST RADIUS: {assessment.score}/100  {_bar(assessment.score)}  "
        f"{_OUTCOME_LABEL[verdict.outcome]}"
    )
    lines = [f"{_ANSI[verdict.outcome]}{_BOLD}{headline}{_RESET}" if colour else headline, ""]
    lines.append(_counts(verdict))
    if assessment.production:
        lines.append("Target looks like production.")
    if assessment.total_reach:
        lines.append(
            f"{assessment.total_reach} resource(s) sit downstream of a destructive change."
        )
    lines.append("")

    rules_by_address = {v.finding.address: v.rule for v in verdict.violations}

    for finding in assessment.ranked:
        icon = _ACTION_ICON[finding.change.action]
        head = (
            f"{icon} {finding.address}  [{finding.score}]  "
            f"{finding.change.action.value} · {finding.category}"
        )
        if colour and finding.is_destructive:
            head = f"\033[31m{head}{_RESET}"
        lines.append(head)
        for reason in finding.reasons:
            lines.append(f"    · {reason}")
        rule = rules_by_address.get(finding.address)
        if rule is not None:
            lines.append(f"    ! policy [{rule.name}] → {rule.outcome.value}: {rule.message}")
        if finding.cascade and finding.is_destructive:
            shown = ", ".join(finding.cascade[:4])
            more = "" if len(finding.cascade) <= 4 else f" (+{len(finding.cascade) - 4} more)"
            lines.append(f"    → cascade: {shown}{more}")
        lines.append("")

    footer = f"{_OUTCOME_LABEL[verdict.outcome]}: {verdict.reason}"
    if verdict.required_approvals:
        footer += f" ({verdict.required_approvals} approvals required)"
    lines.append(f"{_ANSI[verdict.outcome]}{_BOLD}{footer}{_RESET}" if colour else footer)
    return "\n".join(lines)


def render_markdown(verdict: Verdict) -> str:
    assessment = verdict.assessment
    lines = [
        f"## {_OUTCOME_ICON[verdict.outcome]} Blast radius: {assessment.score}/100 — "
        f"{_OUTCOME_LABEL[verdict.outcome]}",
        "",
        f"`{_counts(verdict)}`",
        "",
        f"> {verdict.reason}",
        "",
    ]
    if verdict.required_approvals:
        lines.extend([f"**{verdict.required_approvals} approvals required before apply.**", ""])

    blocking = verdict.blocked
    if blocking:
        lines.extend(["### 🔴 Blocking", ""])
        for violation in blocking:
            lines.append(
                f"- **`{violation.finding.address}`** "
                f"({violation.finding.change.action.value}) — {violation.message}"
            )
        lines.append("")

    lines.extend(
        [
            "| | Resource | Action | Category | Dependents | Score |",
            "| --- | --- | --- | --- | ---: | ---: |",
        ]
    )
    for finding in assessment.ranked:
        lines.append(
            f"| `{_ACTION_ICON[finding.change.action]}` | `{finding.address}` | "
            f"{finding.change.action.value} | {finding.category} | "
            f"{finding.transitive_dependents} | {finding.score} |"
        )

    detailed = [f for f in assessment.ranked if f.reasons]
    if detailed:
        lines.extend(["", "<details><summary>Why these scores</summary>", ""])
        for finding in detailed:
            lines.append(f"**`{finding.address}`** — {finding.score}/100")
            lines.extend(f"- {reason}" for reason in finding.reasons)
            if finding.cascade and finding.is_destructive:
                lines.append(f"- downstream: {', '.join(f'`{a}`' for a in finding.cascade[:8])}")
            lines.append("")
        lines.append("</details>")

    lines.extend(
        [
            "",
            "<sub>Generated by "
            "[tf-blast-radius](https://github.com/s3cretagent/tf-blast-radius)</sub>",
        ]
    )
    return "\n".join(lines)


def _finding_payload(finding: Finding) -> dict[str, object]:
    return {
        "address": finding.address,
        "type": finding.change.type,
        "module": finding.change.module_address,
        "action": finding.change.action.value,
        "category": finding.category,
        "score": finding.score,
        "destructive": finding.is_destructive,
        "direct_dependents": finding.direct_dependents,
        "transitive_dependents": finding.transitive_dependents,
        "cascade": list(finding.cascade),
        "replace_paths": list(finding.change.replace_paths),
        "changed_attributes": list(finding.change.changed_attributes),
        "reasons": list(finding.reasons),
    }


def render_json(verdict: Verdict) -> str:
    assessment = verdict.assessment
    payload = {
        "schema": "tf-blast-radius/v1",
        "summary": {
            "score": assessment.score,
            "outcome": verdict.outcome.value,
            "reason": verdict.reason,
            "required_approvals": verdict.required_approvals,
            "production": assessment.production,
            "terraform_version": assessment.plan.terraform_version,
            "counts": {
                "create": assessment.count(Action.CREATE),
                "update": assessment.count(Action.UPDATE),
                "replace": assessment.count(Action.REPLACE),
                "delete": assessment.count(Action.DELETE),
            },
            "downstream_resources": assessment.total_reach,
        },
        "violations": [
            {
                "address": v.finding.address,
                "rule": v.rule.name,
                "outcome": v.rule.outcome.value,
                "message": v.message,
            }
            for v in verdict.violations
        ],
        "findings": [_finding_payload(f) for f in assessment.ranked],
    }
    return json.dumps(payload, indent=2)


RENDERERS = {"text": render_text, "markdown": render_markdown, "json": render_json}


def render(verdict: Verdict, fmt: str) -> str:
    try:
        renderer = RENDERERS[fmt]
    except KeyError:
        known = ", ".join(sorted(RENDERERS))
        raise ValueError(f"unknown format {fmt!r}; known formats: {known}") from None
    return renderer(verdict)
