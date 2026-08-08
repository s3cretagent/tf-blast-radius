"""Command line interface.

Exit codes:

* ``0`` - allowed, or review-only when ``--fail-on`` is left at ``block``.
* ``1`` - the gate tripped.
* ``2`` - could not run (unreadable plan, malformed policy).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .errors import BlastRadiusError
from .plan import load_plan
from .policy import DEFAULT_POLICY, Outcome, evaluate, load_policy
from .render import RENDERERS, render
from .score import assess

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tf-blast-radius",
        description=(
            "Score a Terraform plan by how badly it can hurt. Infracost tells you what a "
            "plan costs; this tells you what it can take down."
        ),
    )
    parser.add_argument("--version", action="version", version=f"tf-blast-radius {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    score = sub.add_parser("score", help="assess a plan and apply policy")
    score.add_argument("plan", help="path to `terraform show -json tfplan` output")
    score.add_argument("-p", "--policy", help="policy file (defaults to the built-in policy)")
    score.add_argument("-f", "--format", default="text", choices=sorted(RENDERERS))
    score.add_argument("-o", "--output", metavar="PATH", help="write the report to a file")
    score.add_argument(
        "-w", "--workspace", default="", help="workspace name, used to detect production"
    )
    score.add_argument(
        "--production",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force production handling on or off instead of inferring it",
    )
    score.add_argument(
        "--fail-on",
        default="block",
        choices=["block", "review", "never"],
        help="which outcome exits non-zero (default: block)",
    )

    graph = sub.add_parser(
        "graph", help="show what depends on a resource, without scoring anything"
    )
    graph.add_argument("plan")
    graph.add_argument("address", help="resource address to trace, e.g. aws_db_instance.orders")

    sub.add_parser("explain", help="print the built-in policy and scoring model")

    return parser


def cmd_score(args: argparse.Namespace) -> int:
    plan = load_plan(args.plan)
    policy = load_policy(args.policy) if args.policy else DEFAULT_POLICY
    assessment = assess(plan, workspace=args.workspace, production=args.production)
    verdict = evaluate(assessment, policy)

    text = render(verdict, args.format)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(text)

    if args.fail_on == "never":
        return EXIT_OK
    if args.fail_on == "review" and verdict.outcome is not Outcome.ALLOW:
        return EXIT_GATE_FAILED
    if verdict.outcome is Outcome.BLOCK:
        return EXIT_GATE_FAILED
    return EXIT_OK


def cmd_graph(args: argparse.Namespace) -> int:
    plan = load_plan(args.plan)
    known = {c.address for c in plan.changes} | set(plan.dependencies)
    if args.address not in known:
        sample = ", ".join(sorted(known)[:8]) or "(none)"
        raise BlastRadiusError(f"{args.address!r} is not in this plan. Known addresses: {sample}")

    direct = sorted(plan.dependents.get(args.address, set()))
    transitive = sorted(plan.transitive_dependents(args.address))
    indirect = [a for a in transitive if a not in set(direct)]

    print(f"{args.address}")
    print(f"  direct dependents ({len(direct)}):")
    for address in direct or ["(none)"]:
        print(f"    {address}")
    print(f"  additional transitive dependents ({len(indirect)}):")
    for address in indirect or ["(none)"]:
        print(f"    {address}")
    print(f"  total blast radius: {len(transitive)} resource(s)")
    return EXIT_OK


def cmd_explain(_args: argparse.Namespace) -> int:
    from .score import ACTION_SEVERITY, Criticality

    print("Risk = severity x recoverability x reach\n")
    print("Action severity:")
    for action, weight in ACTION_SEVERITY.items():
        print(f"  {action.value:<10} {weight:.2f}")
    print("\nCategory multipliers (applied to destructive actions):")
    for label, value in (
        ("stateful", Criticality.STATEFUL),
        ("serving", Criticality.SERVING),
        ("guardrail", Criticality.GUARDRAIL),
        ("stateless", Criticality.STATELESS),
    ):
        print(f"  {label:<10} {value:.2f}")
    print("\nBuilt-in policy rules:")
    for rule in DEFAULT_POLICY.rules:
        print(f"  [{rule.outcome.value:<6}] {rule.name}")
        if rule.message:
            print(f"           {rule.message}")
    thresholds = DEFAULT_POLICY.thresholds
    print(
        f"\nFallback thresholds: review above {thresholds.review_above}, "
        f"block above {thresholds.block_above}, "
        f"{thresholds.required_approvals} approvals when tripped"
    )
    return EXIT_OK


COMMANDS = {"score": cmd_score, "graph": cmd_graph, "explain": cmd_explain}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except BlastRadiusError as exc:
        print(f"tf-blast-radius: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
