# tf-blast-radius

**Score a Terraform plan by how badly it can hurt — and gate the PR on it.**

`terraform plan` ends with a line like this:

```
Plan: 1 to add, 3 to change, 1 to destroy.
```

That line is the same whether the one destroyed resource is an unreferenced log
group or the RDS instance forty resources hang off. Infracost tells you what a
plan *costs*. `driftctl` tells you what has *drifted*. Nothing tells you the
thing a reviewer actually needs to know at 5pm on a Friday: **how much of this
can I break?**

```console
$ tf-blast-radius score examples/plans/dangerous.json -w prod

BLAST RADIUS: 84/100  █████████████████░░░  BLOCKED

1 to add, 3 to change, 1 to replace, 2 to destroy
Target looks like production.
7 resource(s) sit downstream of a destructive change.

± aws_db_instance.orders  [78]  replace · stateful
    · replaced in place — the existing object is destroyed (forced by change to engine_version)
    · holds state that Terraform cannot recreate — data loss is not recoverable by re-running apply
    · 3 direct and 7 transitive dependent(s) in this configuration
    · targets what looks like a production workspace
    ! policy [stateful-replace] → block: an in-place replacement destroys the existing object first.
      For databases and volumes this is a data-loss event wearing an update's clothing.
    → cascade: aws_appautoscaling_target.checkout, aws_cloudwatch_metric_alarm.orders_errors,
               aws_ecs_service.checkout, aws_ecs_service.orders_api (+3 more)

- aws_iam_policy.legacy_readonly  [54]  delete · guardrail
    · is a security control — removing it breaks nothing today, which is what makes it
      easy to approve by accident
    ! policy [guardrail-removal] → review

- aws_cloudwatch_log_group.retired_worker  [35]  delete · stateless
~ aws_ecs_service.checkout  [18]  update · stateless
+ aws_s3_bucket.build_artifacts  [17]  create · stateful

BLOCKED: blast radius 84/100 — blocked by 1 finding(s) under rule(s): stateful-replace (2 approvals required)
$ echo $?
1
```

That output is real — `make demo` prints it.

---

## The line Terraform does not print

**`aws_db_instance.orders` is a replace, not an update.**

In the plan JSON that change is `"actions": ["delete", "create"]`. There is no
`"replace"` action — Terraform encodes it as a delete followed by a create, and
a parser that reads the list naively sees a create and calls it harmless. The
database is destroyed first; the create does not bring the rows back.

Seven other resources reference it. None of them appear in the plan's own
destroy count, because they are not being destroyed — they are merely about to
point at something that no longer exists.

Both facts are recovered here, and both are asserted by tests:

```python
def test_a_replace_is_recognised_in_both_orderings() -> None:
    assert parse_actions(["delete", "create"]) is Action.REPLACE
    assert parse_actions(["create", "delete"]) is Action.REPLACE   # create_before_destroy
```

---

## How the score works

Risk is the product of three independent things, because any one alone misleads:

**Severity** — what is happening to the object.

| Action | Weight | |
| --- | ---: | --- |
| `delete` | 0.90 | the object stops existing |
| `replace` | 0.85 | the object is destroyed, then a new one is made |
| `update` | 0.25 | adjusted in place |
| `create` | 0.10 | nothing existing is at risk |

**Recoverability** — whether destruction is reversible, by resource category.

| Category | Multiplier | What is lost |
| --- | ---: | --- |
| `stateful` | 1.00 | data no re-apply recreates — databases, buckets, volumes, KMS keys |
| `serving` | 0.75 | live traffic — load balancers, NAT gateways, clusters |
| `guardrail` | 0.70 | a security control — IAM, security groups, CloudTrail, WAF |
| `stateless` | 0.40 | nothing that cannot be rebuilt from code |

Categories are matched as substrings against the Terraform type, so
`aws_elasticache_cluster`, `google_redis_instance` and `azurerm_redis_cache` all
land in `stateful` without maintaining three provider tables.

**Reach** — how much else is wired into it, recovered from the plan's
`configuration` block: the same reference edges Terraform uses to order the
apply, walked in reverse.

Reach saturates. The step from 0 to 5 dependents matters far more than the step
from 40 to 45, and a linear term would let one hub resource flatten every score
in the plan. There is a test pinning that:

```python
def test_reach_saturates_so_one_hub_cannot_dominate_every_score() -> None:
    early = build(5) - build(0)
    late  = build(60) - build(40)
    assert early > late
    assert late == 0
```

### The plan score is the worst change, not the sum

Twenty tag updates must not add up to look like one destroyed database. A summed
score stops meaning anything, and reviewers start ignoring it. The worst single
finding sets the floor; breadth adds a bounded amount (max 10) on top.

---

## Gating

```bash
tf-blast-radius score tfplan.json                          # built-in policy
tf-blast-radius score tfplan.json -p policy.yaml           # your rules
tf-blast-radius score tfplan.json --fail-on review         # stricter gate
```

Rules are evaluated in order and **the first match wins**, so a narrow carve-out
above a broad rule works without any exception machinery:

```yaml
version: 1
thresholds:
  block_above: 70
  review_above: 35
  required_approvals: 2

rules:
  # Carve-out first: sandbox databases are recreated nightly.
  - name: sandbox-databases-are-disposable
    action: allow
    match:
      address: "module.sandbox.*"
      category: stateful

  - name: no-stateful-replace
    action: block
    match:
      category: stateful
      action: replace
    message: >-
      an in-place replacement destroys the existing object first. For databases
      and volumes this is a data-loss event wearing an update's clothing.

  - name: wide-blast-radius
    action: review
    match:
      min_dependents: 8
```

`match` fields are a conjunction — every one stated must hold. `address` and
`type` accept globs. A policy where `review_above` exceeds `block_above` is
rejected at load time, because nothing could ever land in the review band.

**Exit codes:** `0` allowed · `1` gate tripped · `2` could not run.

---

## Tracing the graph on its own

```console
$ tf-blast-radius graph tfplan.json aws_db_instance.orders

aws_db_instance.orders
  direct dependents (3):
    aws_ecs_service.orders_api
    aws_ecs_task_definition.checkout
    aws_lambda_function.reconciler
  additional transitive dependents (4):
    aws_appautoscaling_target.checkout
    aws_cloudwatch_metric_alarm.orders_errors
    aws_ecs_service.checkout
    aws_lambda_event_source_mapping.reconciler
  total blast radius: 7 resource(s)
```

Useful on its own before you touch anything — "what breaks if I take this away?"
is a question worth asking before writing the change, not after.

---

## In CI

```yaml
- run: terraform plan -out=tfplan
- run: terraform show -json tfplan > tfplan.json
- run: tf-blast-radius score tfplan.json -w "${{ env.TF_WORKSPACE }}" -f markdown -o risk.md
```

The workflow in this repo posts the markdown as a **single sticky PR comment**,
updated in place rather than stacked on every push, and requests reviewers when
the verdict is not `allow`.

> Generate the plan with `terraform show -json tfplan`, **not** `terraform plan -json`.
> The latter is a stream of log events with no `configuration` block, so there is
> no dependency graph to walk. The parser says so explicitly if you get it wrong.

---

## What it does not do

**Cross-module edges are approximated.** References inside a module are
module-local and resolved exactly. References that travel between modules go
through variables and outputs, which the plan does not expose as
resource-to-resource edges — those become an edge to the module call. Reach is
therefore a lower bound across module boundaries, never an overestimate.

**Production detection is a hint.** Workspace and address names are pattern
matched. It only ever *raises* a score — a misnamed production workspace must not
read as safe. Use `--production` / `--no-production` when you know better.

**It does not read state.** Everything comes from the plan file, so it needs no
cloud credentials and can run on a fork PR where secrets are unavailable.

---

## Install

```bash
pip install -e '.[dev]'
```

```bash
make test    # 128 tests — no Terraform binary, no cloud, no network
make check   # ruff + mypy --strict + tests
make demo    # the run at the top of this README
make explain # print the scoring model and built-in policy
```

---

## Status

128 tests · 97% coverage · `mypy --strict` clean.

Built by [Shubh Malhotra](https://github.com/s3cretagent) — DevOps / SRE.

MIT licensed.
