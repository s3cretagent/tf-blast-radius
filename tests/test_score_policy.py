from __future__ import annotations

from pathlib import Path

import pytest

from tfblast.errors import PolicyError
from tfblast.plan import Action, parse_plan
from tfblast.policy import DEFAULT_POLICY, Outcome, Rule, Thresholds, evaluate, load_policy
from tfblast.score import assess, classify, looks_like_production, score_change

from .conftest import change, config_resource, plan_payload

# ------------------------------------------------------------- classification --


@pytest.mark.parametrize(
    ("resource_type", "expected"),
    [
        ("aws_db_instance", "stateful"),
        ("aws_rds_cluster", "stateful"),
        ("google_sql_database_instance", "stateful"),
        ("aws_s3_bucket", "stateful"),
        ("aws_dynamodb_table", "stateful"),
        ("azurerm_storage_account", "stateful"),
        ("aws_lb", "serving"),
        ("aws_eks_cluster", "serving"),
        ("aws_nat_gateway", "serving"),
        ("aws_iam_policy", "guardrail"),
        ("aws_security_group", "guardrail"),
        ("aws_cloudtrail", "guardrail"),
        ("aws_cloudwatch_log_group", "stateless"),
        ("aws_sns_topic", "stateless"),
    ],
)
def test_resource_types_classify_by_what_is_lost(resource_type: str, expected: str) -> None:
    assert classify(resource_type)[0] == expected


def test_classification_spans_cloud_providers_without_three_tables() -> None:
    # Substring matching means the aws_/google_/azurerm_ spellings of one idea
    # land in the same category.
    for spelling in ("aws_elasticache_cluster", "google_redis_instance", "azurerm_redis_cache"):
        assert classify(spelling)[0] == "stateful"


@pytest.mark.parametrize("hint", ["prod", "production", "my-prod-cluster", "PRD", "live-eu"])
def test_production_hints_are_detected(hint: str) -> None:
    assert looks_like_production(hint)


@pytest.mark.parametrize("hint", ["staging", "dev", "producer-queue", "reproduction", ""])
def test_non_production_hints_are_not_false_positives(hint: str) -> None:
    assert not looks_like_production(hint)


# ------------------------------------------------------------------- scoring --


def single(resource_type: str, actions: list[str], **kwargs: object):  # type: ignore[no-untyped-def]
    payload = plan_payload([change(f"{resource_type}.x", resource_type, actions)])
    plan = parse_plan(payload)
    return score_change(plan.changes[0], plan, **kwargs)  # type: ignore[arg-type]


def test_destroying_a_database_outscores_destroying_a_log_group() -> None:
    """The whole point, in one assertion.

    Both are '1 to destroy'. Only one of them ends the week badly.
    """
    database = single("aws_db_instance", ["delete"])
    log_group = single("aws_cloudwatch_log_group", ["delete"])
    assert database.score > log_group.score * 2


def test_a_replace_scores_near_a_delete_not_near_an_update() -> None:
    replace = single("aws_db_instance", ["delete", "create"])
    delete = single("aws_db_instance", ["delete"])
    update = single("aws_db_instance", ["update"])
    assert abs(replace.score - delete.score) < 10
    assert replace.score > update.score * 2


def test_creates_score_low() -> None:
    assert single("aws_db_instance", ["create"]).score < 20


def test_reach_raises_the_score() -> None:
    payload = plan_payload(
        [change("aws_db_instance.main", "aws_db_instance", ["delete"])],
        [
            config_resource(f"aws_instance.n{i}", {"db": ["aws_db_instance.main.id"]})
            for i in range(15)
        ],
    )
    plan = parse_plan(payload)
    with_reach = score_change(plan.changes[0], plan)

    isolated = single("aws_db_instance", ["delete"])
    assert with_reach.score > isolated.score
    assert with_reach.transitive_dependents == 15


def test_reach_saturates_so_one_hub_cannot_dominate_every_score() -> None:
    def build(count: int):  # type: ignore[no-untyped-def]
        payload = plan_payload(
            [change("aws_instance.hub", "aws_instance", ["update"])],
            [config_resource(f"aws_x.n{i}", {"h": ["aws_instance.hub.id"]}) for i in range(count)],
        )
        plan = parse_plan(payload)
        return score_change(plan.changes[0], plan).score

    # 0 -> 5 dependents should matter far more than 40 -> 60.
    early = build(5) - build(0)
    late = build(60) - build(40)
    assert early > late
    assert late == 0


def test_production_raises_the_score_but_never_lowers_it() -> None:
    normal = single("aws_db_instance", ["delete"])
    prod = single("aws_db_instance", ["delete"], production=True)
    assert prod.score > normal.score


def test_scores_stay_within_bounds() -> None:
    payload = plan_payload(
        [change("aws_db_instance.main", "aws_db_instance", ["delete"])],
        [config_resource(f"aws_x.n{i}", {"d": ["aws_db_instance.main.id"]}) for i in range(200)],
    )
    plan = parse_plan(payload)
    assert 0 <= score_change(plan.changes[0], plan, production=True).score <= 100


def test_a_guardrail_deletion_explains_why_it_is_easy_to_miss() -> None:
    finding = single("aws_iam_policy", ["delete"])
    assert finding.category == "guardrail"
    assert "easy to approve by accident" in " ".join(finding.reasons)


# ---------------------------------------------------------------- assessment --


def test_plan_score_is_the_worst_change_not_the_sum() -> None:
    """Twenty tag updates must not add up to look like a destroyed database.

    A summed score stops meaning anything and reviewers start ignoring it.
    """
    many_small = assess(
        parse_plan(
            plan_payload(
                [
                    change(f"aws_cloudwatch_log_group.n{i}", "aws_cloudwatch_log_group", ["update"])
                    for i in range(20)
                ]
            )
        )
    )
    one_big = assess(
        parse_plan(plan_payload([change("aws_db_instance.main", "aws_db_instance", ["delete"])]))
    )
    assert many_small.score < one_big.score


def test_breadth_adds_a_bounded_amount() -> None:
    one = assess(parse_plan(plan_payload([change("aws_s3_bucket.a", "aws_s3_bucket", ["delete"])])))
    many = assess(
        parse_plan(
            plan_payload(
                [change(f"aws_s3_bucket.n{i}", "aws_s3_bucket", ["delete"]) for i in range(20)]
            )
        )
    )
    assert many.score > one.score
    assert many.score - one.score <= 10


def test_an_empty_plan_scores_zero() -> None:
    assert assess(parse_plan(plan_payload([]))).score == 0


def test_production_is_inferred_from_the_workspace() -> None:
    plan = parse_plan(plan_payload([change("aws_instance.web", "aws_instance", ["update"])]))
    assert assess(plan, workspace="prod-eu-west-1").production
    assert not assess(plan, workspace="staging").production


def test_production_can_be_forced_either_way() -> None:
    plan = parse_plan(plan_payload([change("aws_instance.web", "aws_instance", ["update"])]))
    assert assess(plan, workspace="staging", production=True).production
    assert not assess(plan, workspace="prod", production=False).production


# -------------------------------------------------------------------- policy --


def destructive_db_plan():  # type: ignore[no-untyped-def]
    return parse_plan(
        plan_payload([change("aws_db_instance.orders", "aws_db_instance", ["delete", "create"])])
    )


def test_the_default_policy_blocks_a_stateful_replace() -> None:
    verdict = evaluate(assess(destructive_db_plan()))
    assert verdict.outcome is Outcome.BLOCK
    assert verdict.outcome.blocks
    assert "stateful-replace" in verdict.reason
    assert verdict.required_approvals == 2


def test_the_default_policy_allows_routine_change() -> None:
    plan = parse_plan(
        plan_payload([change("aws_cloudwatch_log_group.a", "aws_cloudwatch_log_group", ["update"])])
    )
    assert evaluate(assess(plan)).outcome is Outcome.ALLOW


def test_a_guardrail_deletion_lands_in_review() -> None:
    plan = parse_plan(plan_payload([change("aws_iam_policy.legacy", "aws_iam_policy", ["delete"])]))
    assert evaluate(assess(plan)).outcome is Outcome.REVIEW


def test_the_first_matching_rule_wins_so_carve_outs_work() -> None:
    """A specific exception above a broad rule, with no exception logic needed."""
    from tfblast.policy import Policy

    policy = Policy(
        rules=(
            Rule(
                name="sandbox-exception", outcome=Outcome.ALLOW, address="aws_db_instance.scratch*"
            ),
            Rule(name="no-db-destroy", outcome=Outcome.BLOCK, category="stateful", action="delete"),
        ),
        thresholds=Thresholds(block_above=100, review_above=100),
    )
    scratch = assess(
        parse_plan(
            plan_payload([change("aws_db_instance.scratch_1", "aws_db_instance", ["delete"])])
        )
    )
    real = assess(
        parse_plan(plan_payload([change("aws_db_instance.orders", "aws_db_instance", ["delete"])]))
    )
    assert evaluate(scratch, policy).outcome is Outcome.ALLOW
    assert evaluate(real, policy).outcome is Outcome.BLOCK


def test_address_and_type_rules_use_glob_matching() -> None:
    from tfblast.policy import Policy

    policy = Policy(
        rules=(Rule(name="no-buckets", outcome=Outcome.BLOCK, type="*_s3_bucket*"),),
        thresholds=Thresholds(block_above=100, review_above=100),
    )
    plan = parse_plan(
        plan_payload([change("aws_s3_bucket_policy.a", "aws_s3_bucket_policy", ["update"])])
    )
    assert evaluate(assess(plan), policy).outcome is Outcome.BLOCK


def test_the_aggregate_score_can_trip_the_gate_alone() -> None:
    # Many individually-tolerable destructive changes are still a bad day.
    from tfblast.policy import Policy

    policy = Policy(rules=(), thresholds=Thresholds(block_above=30, review_above=10))
    plan = parse_plan(
        plan_payload([change(f"aws_lb.n{i}", "aws_lb", ["delete"]) for i in range(5)])
    )
    assert evaluate(assess(plan), policy).outcome is Outcome.BLOCK


def test_thresholds_decide_when_no_rule_matches() -> None:
    thresholds = Thresholds(block_above=80, review_above=50)
    assert thresholds.outcome_for(10) is Outcome.ALLOW
    assert thresholds.outcome_for(60) is Outcome.REVIEW
    assert thresholds.outcome_for(90) is Outcome.BLOCK


# ------------------------------------------------------------- policy loading --

POLICY = """
version: 1
thresholds:
  block_above: 70
  review_above: 40
  required_approvals: 3
rules:
  - name: no-prod-db-destroy
    action: block
    match:
      type: aws_db_instance
      action: delete
    message: take a snapshot first
"""


def write_policy(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_policy_file_loads(tmp_path: Path) -> None:
    policy = load_policy(write_policy(tmp_path, POLICY))
    assert policy.thresholds.block_above == 70
    assert policy.thresholds.required_approvals == 3
    assert policy.rules[0].name == "no-prod-db-destroy"
    assert policy.rules[0].outcome is Outcome.BLOCK


def test_a_loaded_policy_actually_gates(tmp_path: Path) -> None:
    policy = load_policy(write_policy(tmp_path, POLICY))
    plan = parse_plan(plan_payload([change("aws_db_instance.o", "aws_db_instance", ["delete"])]))
    verdict = evaluate(assess(plan), policy)
    assert verdict.outcome is Outcome.BLOCK
    assert verdict.violations[0].message == "take a snapshot first"


def test_review_above_higher_than_block_above_is_rejected(tmp_path: Path) -> None:
    # Nothing could ever land in the review band, which is a config bug.
    body = POLICY.replace("review_above: 40", "review_above: 90")
    with pytest.raises(PolicyError, match="nothing could ever land in the review band"):
        load_policy(write_policy(tmp_path, body))


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("action: block", "expected one of"),
        ("category", "expected stateful"),
        ("unknown-key", "unknown key"),
        ("no-name", "name: required"),
    ],
)
def test_malformed_policies_are_rejected(tmp_path: Path, mutation: str, match: str) -> None:
    body = {
        "action: block": POLICY.replace("action: block", "action: destroy-everything"),
        "category": POLICY.replace("      type: aws_db_instance", "      category: important"),
        "unknown-key": POLICY.replace("    message:", "    mesage:"),
        "no-name": POLICY.replace("  - name: no-prod-db-destroy\n", "  - \n"),
    }[mutation]
    with pytest.raises(PolicyError, match=match):
        load_policy(write_policy(tmp_path, body))


def test_an_unknown_match_action_is_rejected(tmp_path: Path) -> None:
    body = POLICY.replace("      action: delete", "      action: obliterate")
    with pytest.raises(PolicyError, match="match.action"):
        load_policy(write_policy(tmp_path, body))


def test_an_empty_policy_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="policy is empty"):
        load_policy(write_policy(tmp_path, "\n"))


def test_the_built_in_policy_is_valid_and_opinionated() -> None:
    assert DEFAULT_POLICY.rules
    assert any(r.outcome is Outcome.BLOCK for r in DEFAULT_POLICY.rules)
    assert all(r.message for r in DEFAULT_POLICY.rules), "every rule should explain itself"


# ------------------------------------------------------------ example fixtures --


def test_the_dangerous_example_blocks_on_the_database(dangerous_plan: Path) -> None:
    from tfblast.plan import load_plan

    plan = load_plan(dangerous_plan)
    verdict = evaluate(assess(plan, workspace="prod"))

    assert verdict.outcome is Outcome.BLOCK
    db = next(f for f in verdict.assessment.ranked if f.address == "aws_db_instance.orders")
    assert db.change.action is Action.REPLACE
    assert db.category == "stateful"
    # The DB is a hub: the graph must find what breaks with it.
    assert db.transitive_dependents == 7
    assert "aws_route53_record" not in " ".join(db.cascade)  # not in this fixture
    assert "aws_appautoscaling_target.checkout" in db.cascade


def test_the_routine_example_is_allowed(routine_plan: Path) -> None:
    from tfblast.plan import load_plan

    verdict = evaluate(assess(load_plan(routine_plan), workspace="staging"))
    assert verdict.outcome is Outcome.ALLOW
    assert verdict.assessment.score < 20
