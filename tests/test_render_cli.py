from __future__ import annotations

import json
from pathlib import Path

import pytest

from tfblast import cli
from tfblast.plan import parse_plan
from tfblast.policy import evaluate
from tfblast.render import render, render_json, render_markdown, render_text, use_colour
from tfblast.score import assess

from .conftest import change, plan_payload


def demo_verdict():  # type: ignore[no-untyped-def]
    plan = parse_plan(
        plan_payload(
            [
                change(
                    "aws_db_instance.orders",
                    "aws_db_instance",
                    ["delete", "create"],
                    replace_paths=[["engine_version"]],
                ),
                change("aws_cloudwatch_log_group.old", "aws_cloudwatch_log_group", ["delete"]),
                change("aws_sns_topic.new", "aws_sns_topic", ["create"]),
            ]
        )
    )
    return evaluate(assess(plan, workspace="prod"))


# -------------------------------------------------------------------- render --


def test_text_leads_with_the_verdict_not_the_inventory() -> None:
    text = render_text(demo_verdict(), colour=False)
    assert text.splitlines()[0].startswith("BLAST RADIUS:")
    assert "BLOCKED" in text.splitlines()[0]


def test_text_includes_the_familiar_terraform_counts() -> None:
    text = render_text(demo_verdict(), colour=False)
    assert "1 to add, 0 to change, 1 to replace, 1 to destroy" in text


def test_text_has_no_escape_codes_when_colour_is_off() -> None:
    assert "\033[" not in render_text(demo_verdict(), colour=False)


def test_colour_is_suppressed_in_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "true")
    assert use_colour() is False


def test_markdown_leads_with_the_score_and_states_blocking_findings() -> None:
    md = render_markdown(demo_verdict())
    assert md.startswith("## 🔴 Blast radius:")
    assert "### 🔴 Blocking" in md
    assert "`aws_db_instance.orders`" in md
    assert "approvals required before apply" in md


def test_markdown_table_covers_every_finding() -> None:
    md = render_markdown(demo_verdict())
    for address in ("aws_db_instance.orders", "aws_cloudwatch_log_group.old", "aws_sns_topic.new"):
        assert f"`{address}`" in md


def test_json_is_parseable_and_carries_the_decision() -> None:
    payload = json.loads(render_json(demo_verdict()))
    assert payload["schema"] == "tf-blast-radius/v1"
    assert payload["summary"]["outcome"] == "block"
    assert payload["summary"]["counts"] == {"create": 1, "update": 0, "replace": 1, "delete": 1}
    assert payload["summary"]["production"] is True
    assert payload["violations"][0]["rule"] == "stateful-replace"

    db = next(f for f in payload["findings"] if f["address"] == "aws_db_instance.orders")
    assert db["destructive"] is True
    assert db["category"] == "stateful"
    assert db["replace_paths"] == ["engine_version"]


def test_findings_are_ranked_worst_first() -> None:
    payload = json.loads(render_json(demo_verdict()))
    scores = [f["score"] for f in payload["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_unknown_format_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown format"):
        render(demo_verdict(), "sarif")


# ----------------------------------------------------------------------- cli --


def test_score_blocks_the_dangerous_plan(
    dangerous_plan: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["score", str(dangerous_plan), "-w", "prod"]) == cli.EXIT_GATE_FAILED
    out = capsys.readouterr().out
    assert "BLOCKED" in out
    assert "aws_db_instance.orders" in out


def test_score_allows_the_routine_plan(
    routine_plan: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["score", str(routine_plan), "-w", "staging"]) == cli.EXIT_OK
    assert "LOW RISK" in capsys.readouterr().out


def test_fail_on_review_tightens_the_gate(tmp_path: Path) -> None:
    payload = plan_payload([change("aws_iam_policy.legacy", "aws_iam_policy", ["delete"])])
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert cli.main(["score", str(path)]) == cli.EXIT_OK  # review does not block by default
    assert cli.main(["score", str(path), "--fail-on", "review"]) == cli.EXIT_GATE_FAILED


def test_fail_on_never_always_exits_zero(dangerous_plan: Path) -> None:
    assert cli.main(["score", str(dangerous_plan), "--fail-on", "never"]) == cli.EXIT_OK


def test_no_production_flag_lowers_the_score(
    dangerous_plan: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["score", str(dangerous_plan), "-f", "json", "--production", "--fail-on", "never"])
    with_prod = json.loads(capsys.readouterr().out)["summary"]["score"]
    cli.main(["score", str(dangerous_plan), "-f", "json", "--no-production", "--fail-on", "never"])
    without = json.loads(capsys.readouterr().out)["summary"]["score"]
    assert with_prod > without


def test_a_custom_policy_file_is_honoured(dangerous_plan: Path, tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: 1\nthresholds: {block_above: 99, review_above: 98}\nrules: []\n", encoding="utf-8"
    )
    assert cli.main(["score", str(dangerous_plan), "-p", str(policy)]) == cli.EXIT_OK


def test_score_writes_to_a_file(dangerous_plan: Path, tmp_path: Path) -> None:
    out = tmp_path / "nested" / "report.md"
    cli.main(["score", str(dangerous_plan), "-f", "markdown", "-o", str(out), "--fail-on", "never"])
    assert "Blast radius" in out.read_text()


def test_graph_traces_what_depends_on_a_resource(
    dangerous_plan: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["graph", str(dangerous_plan), "aws_db_instance.orders"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "aws_lambda_function.reconciler" in out
    assert "total blast radius: 7 resource(s)" in out


def test_graph_on_an_unknown_address_lists_what_exists(
    dangerous_plan: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["graph", str(dangerous_plan), "aws_db_instance.typo"]) == cli.EXIT_ERROR
    assert "Known addresses" in capsys.readouterr().err


def test_explain_prints_the_model(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["explain"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "severity" in out
    assert "stateful-replace" in out


def test_a_bad_plan_exits_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "plan.json"
    bad.write_text("{}", encoding="utf-8")
    assert cli.main(["score", str(bad)]) == cli.EXIT_ERROR
    assert "tf-blast-radius:" in capsys.readouterr().err


def test_version_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0


def test_a_subcommand_is_required() -> None:
    with pytest.raises(SystemExit):
        cli.main([])
