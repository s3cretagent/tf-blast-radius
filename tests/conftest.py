"""Shared fixtures. No Terraform binary, no cloud, no network."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def change(
    address: str,
    resource_type: str,
    actions: list[str],
    *,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    replace_paths: list[list[str]] | None = None,
    module_address: str = "",
) -> dict[str, Any]:
    """Build one ``resource_changes`` entry."""
    entry: dict[str, Any] = {
        "address": address,
        "mode": "managed",
        "type": resource_type,
        "name": address.split(".")[-1],
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": actions, "before": before, "after": after},
    }
    if replace_paths:
        entry["change"]["replace_paths"] = replace_paths
    if module_address:
        entry["module_address"] = module_address
    return entry


def config_resource(
    address: str,
    references: dict[str, list[str]] | None = None,
    depends_on: list[str] | None = None,
) -> dict[str, Any]:
    """Build one ``configuration.root_module.resources`` entry."""
    parts = address.split(".")
    entry: dict[str, Any] = {
        "address": address,
        "mode": "managed",
        "type": parts[0],
        "name": parts[-1],
        "expressions": {key: {"references": refs} for key, refs in (references or {}).items()},
    }
    if depends_on:
        entry["depends_on"] = depends_on
    return entry


def plan_payload(
    changes: list[dict[str, Any]],
    resources: list[dict[str, Any]] | None = None,
    *,
    format_version: str = "1.2",
) -> dict[str, Any]:
    return {
        "format_version": format_version,
        "terraform_version": "1.9.5",
        "resource_changes": changes,
        "configuration": {"root_module": {"resources": resources or []}},
    }


def write_plan(tmp_path: Path, payload: dict[str, Any]) -> Path:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.fixture
def examples_dir() -> Path:
    return EXAMPLES


@pytest.fixture
def dangerous_plan(examples_dir: Path) -> Path:
    return examples_dir / "plans" / "dangerous.json"


@pytest.fixture
def routine_plan(examples_dir: Path) -> Path:
    return examples_dir / "plans" / "routine.json"
