from __future__ import annotations

from pathlib import Path

import pytest

from tfblast.errors import PlanError
from tfblast.plan import Action, load_plan, normalise_reference, parse_actions, parse_plan

from .conftest import change, config_resource, plan_payload, write_plan

# -------------------------------------------------------------------- actions --


@pytest.mark.parametrize(
    ("actions", "expected"),
    [
        (["no-op"], Action.NOOP),
        (["create"], Action.CREATE),
        (["update"], Action.UPDATE),
        (["delete"], Action.DELETE),
        (["read"], Action.READ),
        (["delete", "create"], Action.REPLACE),
        (["create", "delete"], Action.REPLACE),
    ],
)
def test_action_lists_collapse_to_a_verdict(actions: list[str], expected: Action) -> None:
    assert parse_actions(actions) == expected


def test_a_replace_is_recognised_in_both_orderings() -> None:
    """create_before_destroy flips the order; both are still a replace.

    Reading ["create", "delete"] as a create is how a destroyed database gets
    reviewed as a harmless addition.
    """
    assert parse_actions(["delete", "create"]) is Action.REPLACE
    assert parse_actions(["create", "delete"]) is Action.REPLACE


@pytest.mark.parametrize("actions", [[], None, "delete", ["frobnicate"], ["update", "read"]])
def test_malformed_actions_raise(actions: object) -> None:
    with pytest.raises(PlanError):
        parse_actions(actions)


@pytest.mark.parametrize("action", [Action.DELETE, Action.REPLACE])
def test_destructive_actions_are_flagged(action: Action) -> None:
    assert action.destroys_data


@pytest.mark.parametrize("action", [Action.CREATE, Action.UPDATE, Action.NOOP, Action.READ])
def test_non_destructive_actions_are_not(action: Action) -> None:
    assert not action.destroys_data


# ----------------------------------------------------------------- references --


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("aws_security_group.db", "aws_security_group.db"),
        ("aws_security_group.db.id", "aws_security_group.db"),
        ("aws_db_instance.orders.endpoint", "aws_db_instance.orders"),
        ("data.aws_ami.ubuntu.id", "data.aws_ami.ubuntu"),
        ("module.network.vpc_id", "module.network"),
    ],
)
def test_references_normalise_to_addresses(reference: str, expected: str) -> None:
    assert normalise_reference(reference) == expected


@pytest.mark.parametrize(
    "reference",
    ["var.vpc_id", "local.name", "each.key", "count.index", "path.module", "self.id", "", "aws_x"],
)
def test_non_resource_references_are_dropped(reference: str) -> None:
    assert normalise_reference(reference) is None


def test_doubled_references_collapse_to_one_edge() -> None:
    # Terraform emits both `aws_x.y.id` and `aws_x.y`; counting both would
    # double every edge in the graph.
    payload = plan_payload(
        [change("aws_instance.web", "aws_instance", ["update"])],
        [
            config_resource(
                "aws_instance.web",
                {"vpc_security_group_ids": ["aws_security_group.web.id", "aws_security_group.web"]},
            )
        ],
    )
    plan = parse_plan(payload)
    assert plan.dependencies["aws_instance.web"] == {"aws_security_group.web"}


# ---------------------------------------------------------------------- graph --


def sample_graph_payload() -> dict[str, object]:
    """web -> lb -> dns, plus a lambda hanging off the db."""
    return plan_payload(
        [change("aws_db_instance.main", "aws_db_instance", ["delete", "create"])],
        [
            config_resource("aws_db_instance.main", {"sg": ["aws_security_group.db"]}),
            config_resource("aws_instance.web", {"db": ["aws_db_instance.main.endpoint"]}),
            config_resource("aws_lb_target_group_attachment.web", {"t": ["aws_instance.web.id"]}),
            config_resource(
                "aws_route53_record.app", {"lb": ["aws_lb_target_group_attachment.web"]}
            ),
            config_resource("aws_lambda_function.jobs", {"db": ["aws_db_instance.main.address"]}),
        ],
    )


def test_dependents_invert_the_dependency_graph() -> None:
    plan = parse_plan(sample_graph_payload())
    assert plan.dependents["aws_db_instance.main"] == {
        "aws_instance.web",
        "aws_lambda_function.jobs",
    }


def test_transitive_dependents_follow_the_chain() -> None:
    plan = parse_plan(sample_graph_payload())
    assert plan.transitive_dependents("aws_db_instance.main") == {
        "aws_instance.web",
        "aws_lb_target_group_attachment.web",
        "aws_route53_record.app",
        "aws_lambda_function.jobs",
    }


def test_transitive_walk_excludes_the_resource_itself() -> None:
    plan = parse_plan(sample_graph_payload())
    assert "aws_db_instance.main" not in plan.transitive_dependents("aws_db_instance.main")


def test_a_cycle_terminates_instead_of_recursing_forever() -> None:
    # Terraform rejects real cycles, but module-boundary approximation can
    # introduce one, and a stack overflow is a poor way to report that.
    payload = plan_payload(
        [change("aws_a.one", "aws_a", ["update"])],
        [
            config_resource("aws_a.one", {"x": ["aws_b.two"]}),
            config_resource("aws_b.two", {"x": ["aws_a.one"]}),
        ],
    )
    plan = parse_plan(payload)
    assert plan.transitive_dependents("aws_a.one") == {"aws_b.two"}


def test_depends_on_creates_edges_too() -> None:
    payload = plan_payload(
        [change("aws_instance.web", "aws_instance", ["update"])],
        [config_resource("aws_instance.web", depends_on=["aws_db_instance.main"])],
    )
    plan = parse_plan(payload)
    assert "aws_db_instance.main" in plan.dependencies["aws_instance.web"]


def test_module_resources_are_walked_and_addresses_qualified() -> None:
    payload = plan_payload(
        [change("module.db.aws_db_instance.main", "aws_db_instance", ["update"])]
    )
    payload["configuration"] = {
        "root_module": {
            "resources": [],
            "module_calls": {
                "db": {
                    "module": {
                        "resources": [
                            config_resource(
                                "aws_db_instance.main", {"sg": ["aws_security_group.db"]}
                            ),
                            config_resource(
                                "aws_instance.reader", {"db": ["aws_db_instance.main.id"]}
                            ),
                        ]
                    }
                }
            },
        }
    }
    plan = parse_plan(payload)
    assert plan.dependencies["module.db.aws_db_instance.main"] == {
        "module.db.aws_security_group.db"
    }
    assert plan.transitive_dependents("module.db.aws_db_instance.main") == {
        "module.db.aws_instance.reader"
    }


# ------------------------------------------------------------------- parsing --


def test_replace_paths_and_reason_are_captured() -> None:
    payload = plan_payload(
        [
            change(
                "aws_db_instance.main",
                "aws_db_instance",
                ["delete", "create"],
                replace_paths=[["engine_version"]],
            )
        ]
    )
    payload["resource_changes"][0]["action_reason"] = "replace_because_cannot_update"
    plan = parse_plan(payload)
    assert plan.changes[0].replace_paths == ("engine_version",)
    assert "engine_version" in plan.changes[0].why_replaced


def test_changed_attributes_are_a_top_level_diff() -> None:
    payload = plan_payload(
        [
            change(
                "aws_instance.web",
                "aws_instance",
                ["update"],
                before={"size": "t3.small", "ami": "ami-1", "name": "web"},
                after={"size": "t3.large", "ami": "ami-1", "name": "web"},
            )
        ]
    )
    assert parse_plan(payload).changes[0].changed_attributes == ("size",)


def test_noops_and_reads_are_excluded_from_actionable_changes() -> None:
    payload = plan_payload(
        [
            change("aws_instance.a", "aws_instance", ["no-op"]),
            change("data.aws_ami.b", "aws_ami", ["read"]),
            change("aws_instance.c", "aws_instance", ["update"]),
        ]
    )
    plan = parse_plan(payload)
    assert len(plan.changes) == 3
    assert [c.address for c in plan.actionable] == ["aws_instance.c"]


def test_a_plan_without_resource_changes_explains_the_right_command() -> None:
    with pytest.raises(PlanError, match="terraform show -json"):
        parse_plan({"format_version": "1.2"})


def test_an_unsupported_format_version_is_rejected() -> None:
    with pytest.raises(PlanError, match="unsupported plan format_version"):
        parse_plan(plan_payload([], format_version="9.0"))


def test_a_non_object_plan_is_rejected() -> None:
    with pytest.raises(PlanError, match="must be a JSON object"):
        parse_plan([1, 2, 3])


def test_a_change_without_a_change_block_is_rejected() -> None:
    with pytest.raises(PlanError, match="has no change block"):
        parse_plan({"resource_changes": [{"address": "aws_instance.web"}]})


def test_loading_a_non_json_file_suggests_the_likely_mistake(tmp_path: Path) -> None:
    path = tmp_path / "plan.json"
    path.write_text("Terraform will perform the following actions:", encoding="utf-8")
    with pytest.raises(PlanError, match="Did you pipe"):
        load_plan(path)


def test_loading_a_missing_file_is_reported_cleanly(tmp_path: Path) -> None:
    with pytest.raises(PlanError, match="cannot read plan"):
        load_plan(tmp_path / "nope.json")


def test_round_trips_through_a_file(tmp_path: Path) -> None:
    path = write_plan(
        tmp_path, plan_payload([change("aws_instance.web", "aws_instance", ["create"])])
    )
    plan = load_plan(path)
    assert plan.terraform_version == "1.9.5"
    assert plan.count(Action.CREATE) == 1
