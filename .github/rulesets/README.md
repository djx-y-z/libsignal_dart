# Repository rulesets & release protection

This directory holds the GitHub **repository rulesets** as committed JSON — the
source of truth, visible and editable in-repo — plus this runbook. Apply them
with:

```bash
make setup-repo-protections
```

which reads every `*.json` here, creates it on GitHub (idempotent by ruleset
name — existing ones are skipped unless `--update`), and configures the
`native-build` environment with you as a required reviewer.

Rulesets and environments live **on GitHub**, not in a repo file — GitHub does
not apply this directory automatically. `make setup-repo-protections` (or the
manual `gh api` calls below) pushes them there, so run it **after the GitHub repo
exists** (first push). A wrong bypass actor can lock a maintainer out of
releasing, so review before applying. All commands assume the
[`gh`](https://cli.github.com) CLI authenticated as a repo **admin**; replace
`djx-y-z/libsignal_dart` if you forked.

## Why this exists (the supply-chain gap)

The native binaries that every consumer downloads at build time
(`hook/build.dart` → GitHub Release `libsignal_frb-<crate>`) are produced by
`.github/workflows/build-libsignal.yml`, which publishes a release when **either**
a `libsignal_frb-*` tag is pushed **or** it is started manually
(`workflow_dispatch`). Without protection, any collaborator with `write` could
push a `libsignal_frb-*` / `v*` tag or dispatch the workflow and ship a native
binary to consumers with no review — a supply-chain risk for a crypto library.
By contrast the pub.dev publish (`publish.yml`) is gated by the `pub.dev`
environment's required reviewers. The rulesets + `native-build` environment below
bring the native build up to the same bar.

## The rulesets

Repository roles referenced by `actor_id`: Read = 1, Triage = 2, Write = 3,
Maintain = 4, **Admin = 5**.

| File | Ruleset | Target | Rules | Bypass |
|------|---------|--------|-------|--------|
| `protect-main.json` | Protect main branch | `~DEFAULT_BRANCH` | pull_request (0 approvals), non_fast_forward, deletion | Admin (5) |
| `signing-commit.json` | Signing commit | `~ALL` branches | required_signatures, non_fast_forward | the update GitHub App (Integration) |
| `delete-branches.json` | Delete branches | `~ALL` branches | deletion | Admin (5) |
| `protect-release-tags.json` | Protect release tags | all tags (`~ALL`) | creation, update, deletion, required_signatures | Admin (5), Maintain (4) |

The load-bearing new one is **Protect release tags**. It targets **all tags**
(`~ALL`), so `creation` restricts creating *any* tag to Admin/Maintain — which
covers the release-triggering `libsignal_frb-*` (native build) and `v*` (pub.dev)
tags and every other tag, so no `write` collaborator can mint a tag that starts a
publish. (Only `libsignal_frb-*`/`v*` actually trigger a workflow; the `~ALL`
scope is defense-in-depth so the rule never lags behind a new trigger pattern.)
`update`+`deletion` make tags immutable; `required_signatures` is
belt-and-suspenders (`make release-frb` / `make release` already sign tags). If
GitHub ever rejects `required_signatures` on a tag target, drop that one rule —
`creation`/`update`/`deletion` carry the protection.

## Apply

```bash
make setup-repo-protections                   # apply all (skips existing rulesets)
make setup-repo-protections ARGS="--update"   # overwrite existing rulesets (PUT)
make setup-repo-protections ARGS="--no-environment"   # rulesets only
```

Manual equivalent (per file), if you can't use the script:

```bash
gh api --method POST repos/djx-y-z/libsignal_dart/rulesets \
  --input .github/rulesets/protect-release-tags.json
```

**Verify / roll back:**

```bash
gh api repos/djx-y-z/libsignal_dart/rulesets --jq '.[] | "\(.id)\t\(.name)"'
gh api --method DELETE repos/djx-y-z/libsignal_dart/rulesets/<ID>   # roll back one
```

Prefer a dry run? Set `"enforcement": "evaluate"` in a JSON file, apply, watch the
ruleset "insights", then flip back to `"active"` and re-run with `--update`.

## The `native-build` environment (approval gate)

A tag ruleset does **not** cover the `workflow_dispatch` path, so
`build-libsignal.yml`'s `create-release` job runs in the `native-build`
environment. `make setup-repo-protections` creates that environment and adds you
as a required reviewer; until reviewers exist the gate is inactive (GitHub
auto-creates the environment unprotected, which is safe). To also forbid entering
it off an arbitrary ref, add a deployment-branch policy allowing only
`libsignal_frb-*` (Settings → Environments → native-build).

> Environment protections (required reviewers, deployment-branch policy) are not
> expressible as a committed file, so the script sets them via the environments
> API and this runbook is their source of truth.

## Project-specific / optional fields

- **`signing-commit.json` bypass.** A GitHub App that pushes commits (e.g. the
  `check-libsignal-updates.yml` update bot) needs a bypass entry only if it
  pushes *unsigned* refs. Find its Integration id and edit the file's
  `bypass_actors`:
  ```bash
  gh api repos/djx-y-z/libsignal_dart/installations --jq '.installations[].app_id'
  ```
  If the bot commits via the API with `sign-commits: true` (already signed), it
  may not need the bypass at all — remove the entry.

## Optional hardening (review, not required)

- **"Protect main" approvals.** With a solo maintainer, 0 required approvals is
  only a "use PRs" hygiene gate — the Admin bypasses it anyway. Once you add
  non-admin write collaborators, raise `required_approving_review_count` to 1 and
  enable `require_last_push_approval` in `protect-main.json`, then re-run with
  `--update`.

## Residual risks (out of scope for rulesets)

- **Build-time code execution.** On a `workflow_dispatch` run off an attacker's
  branch, their `build.rs` / proc-macros still *execute* in the build runners
  before the `create-release` approval gate. Those jobs carry **no secrets**, so
  the blast radius is CPU, not credential theft — keep it that way.
- **Binary authenticity.** Consumers still verify downloads by SHA256 only
  (checksums live in the same release). A detached signature + SLSA provenance is
  the real authenticity fix — see `SECURITY.md → Supply Chain Security`.
