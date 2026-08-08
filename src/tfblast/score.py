"""The risk model.

Existing tools answer adjacent questions. Infracost tells you what a plan
*costs*. `terraform plan` tells you what it *changes*. Neither answers the one a
reviewer actually needs at 5pm on a Friday: **how badly can this hurt?**

Risk here is the product of three independent things, because any one of them
alone is misleading:

* **Severity** — is the object destroyed, or merely adjusted?
* **Recoverability** — if it is destroyed, does the data come back?
* **Reach** — how much else is wired into it?

Deleting an unreferenced CloudWatch log group and deleting the RDS instance
forty resources hang off are both "1 to destroy". Only one of them ends the
week badly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .plan import Action, Plan, ResourceChange

# --------------------------------------------------------------------- severity --

#: How much of the risk each action contributes before anything else is applied.
ACTION_SEVERITY: dict[Action, float] = {
    Action.NOOP: 0.0,
    Action.READ: 0.0,
    Action.CREATE: 0.10,
    Action.UPDATE: 0.25,
    Action.DELETE: 0.90,
    # A replace is a delete plus a create, and the create does not bring the
    # data back. It scores marginally below a bare delete only because the
    # resource is at least intended to exist afterwards.
    Action.REPLACE: 0.85,
}


# ------------------------------------------------------------------ criticality --

#: Resource types whose destruction loses state that cannot be recreated from
#: code. Matched as substrings against the Terraform type, so this covers the
#: aws_/google_/azurerm_ spellings of the same idea without three tables.
STATEFUL_PATTERNS: tuple[str, ...] = (
    "db_instance",
    "rds_cluster",
    "db_cluster",
    "sql_database",
    "sql_database_instance",
    "elasticache",
    "redis",
    "memorystore",
    "dynamodb_table",
    "documentdb",
    "docdb_cluster",
    "s3_bucket",
    "storage_bucket",
    "storage_account",
    "ebs_volume",
    "persistent_disk",
    "efs_file_system",
    "elasticsearch_domain",
    "opensearch_domain",
    "msk_cluster",
    "kafka",
    "kms_key",
    "secretsmanager_secret",
    "ssm_parameter",
    "backup_vault",
    "glacier_vault",
    "redshift_cluster",
    "neptune_cluster",
    "cloudsql",
    "bigtable",
    "spanner",
)

#: Types whose destruction interrupts serving traffic but loses no data. Bad,
#: recoverable, and therefore scored below stateful.
SERVING_PATTERNS: tuple[str, ...] = (
    "lb",
    "load_balancer",
    "elb",
    "alb",
    "target_group",
    "nat_gateway",
    "internet_gateway",
    "vpn_",
    "transit_gateway",
    "route53_zone",
    "dns_managed_zone",
    "cloudfront_distribution",
    "api_gateway",
    "eks_cluster",
    "gke_cluster",
    "container_cluster",
    "ecs_cluster",
    "autoscaling_group",
    "node_group",
    "instance_group",
)

#: Types whose destruction silently removes a control. Nothing breaks today,
#: which is exactly what makes them easy to approve by accident.
GUARDRAIL_PATTERNS: tuple[str, ...] = (
    "iam_policy",
    "iam_role",
    "security_group",
    "network_acl",
    "firewall",
    "waf",
    "guardduty",
    "cloudtrail",
    "config_rule",
    "flow_log",
    "bucket_public_access_block",
    "bucket_versioning",
)


class Criticality:
    """Multipliers applied to a destructive action's severity."""

    STATEFUL = 1.0
    SERVING = 0.75
    GUARDRAIL = 0.70
    STATELESS = 0.40


def classify(resource_type: str) -> tuple[str, float]:
    """Return a human label and multiplier for a Terraform resource type."""
    lowered = resource_type.lower()
    if any(pattern in lowered for pattern in STATEFUL_PATTERNS):
        return "stateful", Criticality.STATEFUL
    if any(pattern in lowered for pattern in SERVING_PATTERNS):
        return "serving", Criticality.SERVING
    if any(pattern in lowered for pattern in GUARDRAIL_PATTERNS):
        return "guardrail", Criticality.GUARDRAIL
    return "stateless", Criticality.STATELESS


# ------------------------------------------------------------------ environment --

_PROD = re.compile(r"(^|[^a-z])(prod|production|prd|live)([^a-z]|$)", re.IGNORECASE)


def looks_like_production(*hints: str) -> bool:
    """Heuristic production detection from workspace names, addresses, or tags.

    Deliberately a *hint*, not a source of truth. It raises the score of
    anything that smells like production; it never lowers the score of anything
    that does not, because a misnamed prod workspace must not read as safe.
    """
    return any(hint and _PROD.search(hint) for hint in hints)


# ----------------------------------------------------------------------- scoring --


@dataclass(frozen=True, slots=True)
class Finding:
    """One scored change."""

    change: ResourceChange
    score: int
    category: str
    direct_dependents: int
    transitive_dependents: int
    cascade: tuple[str, ...] = ()
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def address(self) -> str:
        return self.change.address

    @property
    def is_destructive(self) -> bool:
        return self.change.action.destroys_data


@dataclass(frozen=True, slots=True)
class Assessment:
    """The whole plan, scored."""

    findings: tuple[Finding, ...]
    plan: Plan
    production: bool = False

    @property
    def score(self) -> int:
        """The plan's overall risk: its single worst change, nudged by volume.

        Deliberately *not* a sum. Twenty low-risk tag updates must not add up to
        look like one destroyed database, or the number stops meaning anything
        and reviewers start ignoring it. The worst change sets the floor; breadth
        adds a bounded amount on top.
        """
        if not self.findings:
            return 0
        worst = max(f.score for f in self.findings)
        destructive = sum(1 for f in self.findings if f.is_destructive)
        breadth = min(destructive * 2, 10)
        return min(worst + breadth, 100)

    @property
    def ranked(self) -> tuple[Finding, ...]:
        return tuple(sorted(self.findings, key=lambda f: f.score, reverse=True))

    @property
    def destructive(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.ranked if f.is_destructive)

    def count(self, action: Action) -> int:
        return sum(1 for f in self.findings if f.change.action is action)

    @property
    def total_reach(self) -> int:
        """Distinct resources downstream of any destructive change."""
        reached: set[str] = set()
        for finding in self.destructive:
            reached.update(finding.cascade)
        return len(reached)


def score_change(change: ResourceChange, plan: Plan, *, production: bool = False) -> Finding:
    """Score a single change from severity x criticality x reach."""
    category, multiplier = classify(change.type)
    severity = ACTION_SEVERITY[change.action]

    dependents = plan.dependents.get(change.address, set())
    transitive = plan.transitive_dependents(change.address)

    reasons: list[str] = []

    if change.action is Action.REPLACE:
        detail = change.why_replaced
        reasons.append(f"replaced in place — the existing object is destroyed ({detail})")
    elif change.action is Action.DELETE:
        reasons.append("destroyed")

    if change.action.destroys_data and category == "stateful":
        reasons.append(
            "holds state that Terraform cannot recreate — data loss is not "
            "recoverable by re-running apply"
        )
    elif change.action.destroys_data and category == "serving":
        reasons.append("carries live traffic — expect an interruption during the apply")
    elif change.action.destroys_data and category == "guardrail":
        reasons.append(
            "is a security control — removing it breaks nothing today, which is "
            "what makes it easy to approve by accident"
        )

    base = severity * (multiplier if severity >= ACTION_SEVERITY[Action.UPDATE] else 1.0)

    # Reach is logarithmic-ish: the step from 0 to 5 dependents matters far more
    # than the step from 40 to 45, and a linear term would let one hub resource
    # saturate every score in the plan.
    reach = len(transitive)
    reach_factor = min(reach / 20.0, 1.0)
    if reach:
        reasons.append(
            f"{len(dependents)} direct and {reach} transitive dependent(s) in this configuration"
        )

    score = base * 70 + reach_factor * 25
    if production and severity > 0:
        score += 10
        reasons.append("targets what looks like a production workspace")

    if change.action is Action.UPDATE and change.changed_attributes:
        shown = ", ".join(change.changed_attributes[:5])
        more = (
            ""
            if len(change.changed_attributes) <= 5
            else f" (+{len(change.changed_attributes) - 5} more)"
        )
        reasons.append(f"changes {shown}{more}")

    return Finding(
        change=change,
        score=max(0, min(round(score), 100)),
        category=category,
        direct_dependents=len(dependents),
        transitive_dependents=reach,
        cascade=tuple(sorted(transitive)),
        reasons=tuple(reasons),
    )


def assess(plan: Plan, *, workspace: str = "", production: bool | None = None) -> Assessment:
    """Score every actionable change in a plan."""
    if production is None:
        production = looks_like_production(workspace, *[c.address for c in plan.actionable])

    findings = tuple(score_change(c, plan, production=production) for c in plan.actionable)
    return Assessment(findings=findings, plan=plan, production=production)
