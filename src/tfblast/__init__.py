"""tf-blast-radius — score a Terraform plan by how badly it can hurt.

`terraform plan` says "1 to destroy". It does not say whether that one is an
unreferenced log group or the RDS instance forty resources hang off. This scores
the difference, and gates on it.
"""

from __future__ import annotations

__version__ = "0.2.0"

from .errors import BlastRadiusError, PlanError, PolicyError
from .plan import Action, Plan, ResourceChange, load_plan, parse_plan
from .policy import DEFAULT_POLICY, Outcome, Policy, Rule, Verdict, evaluate, load_policy
from .render import render
from .score import Assessment, Finding, assess, classify, score_change

__all__ = [
    "DEFAULT_POLICY",
    "Action",
    "Assessment",
    "BlastRadiusError",
    "Finding",
    "Outcome",
    "Plan",
    "PlanError",
    "Policy",
    "PolicyError",
    "ResourceChange",
    "Rule",
    "Verdict",
    "__version__",
    "assess",
    "classify",
    "evaluate",
    "load_plan",
    "load_policy",
    "parse_plan",
    "render",
    "score_change",
]
