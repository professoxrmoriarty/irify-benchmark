# PR Triage & Split

Split a feature branch that has accumulated mixed-concern commits (the feature itself + incidental bug fixes discovered while iterating in a live environment) into clean, independently-reviewable PRs — without losing the iteration speed that comes from fixing things as you find them.

## When to use this skill

Use this skill whenever a feature branch has 3+ commits that span more than one concern and the branch is approaching PR-readiness. The classic trigger: "I branched to do feature X, but along the way I had to fix bugs Y and Z just to get the environment running / the UI legible / the scan to succeed, and now my branch is a mixed bag."

This is NOT a code-quality or linting skill. It is purely about **commit triage and branch surgery** — deciding which commits belong in which PR, then executing the git operations to produce clean branches.

## Why this matters

Reviewers hate mixed PRs. A PR titled "feat: AI batch judgement" that also silently changes SSH auth logic and Tag colors forces the reviewer to context-switch across unrelated concerns, makes rollback risky (can't revert just the AI part), and pollutes the feature branch's git history.

But forcing yourself to stop and create a separate fix branch every time you hit a bug while iterating **kills iteration speed** — you'd spend half your time on branch bookkeeping instead of making progress. The pragmatic answer: fix in-place when you find it (fast), then triage before PR (clean). This skill is the "triage before PR" step.

## Prerequisites

Before running this skill, confirm:

1. **The feature branch is committed and clean** (`git status` shows no uncommitted changes). If there are uncommitted changes, commit or stash them first — you cannot triage a moving target.
2. **You know the baseline branch** the feature branched from. For legion-rewrite work this is `origin/legion_rewrite_base`; for yaklang refactor work it's `origin/go0p/refactor/scannode`; for main-track work it's `origin/main`. The AGENTS.md "Refactoring Baseline Branches" table is the source of truth.
3. **You have fetched the latest baseline** (`git fetch origin <baseline>`). Splitting against a stale baseline produces branches that won't merge cleanly.

## The triage process

### Step 1: Inventory — what's on this branch?

List every commit that the feature branch has over the baseline, with its files:

```bash
git log --oneline origin/<baseline>..HEAD
```

For each commit, get its file footprint:

```bash
git show --stat <commit-hash> --oneline
```

Record this in a triage table (mentally or on paper). The goal is to see, at a glance, what each commit touches.

### Step 2: Classify — three buckets

Read each commit's message AND its file diff (not just the stat — the message can lie). Classify into exactly three buckets:

| Bucket | Meaning | Destiny |
|--------|---------|---------|
| **F — Feature** | Commits that are the branch's stated purpose. This is the work the branch name promises. | Stays on the feature branch → the feature PR. |
| **B — Bug fix (general)** | Commits that fix a real bug any user would hit, regardless of whether the feature exists. These are not dependencies of the feature — they just happened to be found while iterating. | Cherry-pick to a `fix/<scope>/<topic>` branch → independent fix PR, merged to baseline **before** the feature PR. |
| **D — Dependency of the feature** | Commits that fix a bug the feature *itself* introduced or that the feature *cannot work without*. These are not general bugs — they only make sense in the feature's context. | Stays on the feature branch → part of the feature PR. |

**How to tell B from D:** Ask "would a user on `main`/baseline, without my feature, hit this bug?" If yes → B (general bug fix, deserves its own PR). If no, the bug only exists because of the feature's new code path → D (part of the feature).

**Edge case — squash candidates:** If multiple commits fix the same logical issue (e.g. 4 commits all tweaking Tag colors until the rendering was right), squash them into one before cherry-picking. The intermediate attempts are not useful history for a reviewer.

### Step 3: Split — execute the git surgery

Work in the **main repository working directory** (not inside a worktree), because you'll need to create new branches from the baseline.

#### 3a. Create fix branches for bucket B

For each B-classified commit (or squashed group):

```bash
# Fetch latest baseline (mandatory — never branch from stale)
git fetch origin <baseline>

# Create a fix branch from the fresh baseline
git checkout -b fix/<scope>/<topic> origin/<baseline>

# Cherry-pick the commit (or squashed group)
git cherry-pick <commit-hash>
# For squash of multiple commits:
#   git cherry-pick --no-commit <hash1> <hash2> ...
#   git commit -m "<unified message>"
```

The branch naming convention (from AGENTS.md):
- legion backend/frontend: `fix/<scope>/<topic>` (e.g. `fix/ssh-source-auth-git-user`)
- yaklang: `fix/yaklang/<topic>`
- console UI: `fix/console/<topic>`

Create the fix branches as worktrees if parallel work is expected:
```bash
git worktree add -b fix/<scope>/<topic> ../.worktrees/<topic> origin/<baseline>
```

#### 3b. Clean the feature branch

After cherry-picking all B commits out, rebase the feature branch onto the latest baseline and drop the commits that are now on fix branches:

```bash
git checkout <feature-branch>
git fetch origin <baseline>
git rebase -i origin/<baseline>
```

In the rebase todo list:
- **Drop** commits that were cherry-picked to fix branches (they'll arrive via the fix PRs).
- **Keep** F and D commits (the feature's own work).
- **Squash** any D commits that are just incremental attempts at the same change.

If the fix PRs have already been merged to the baseline by the time you rebase, the cherry-picked commits will **not** appear as conflicts — git rebase auto-skips commits whose patch is already in the baseline (it detects the same change-id). This is why fix PRs should merge **first**.

#### 3c. Verify

After the split:

```bash
# Each fix branch should contain only its fix:
git log --oneline origin/<baseline>..fix/<scope>/<topic>

# The feature branch should contain only F + D commits:
git log --oneline origin/<baseline>..<feature-branch>

# No commit should appear on two branches (except via merge):
# Check for duplicate patch-ids:
git log --oneline origin/<baseline>..HEAD --format="%H" | while read h; do
  git cherry origin/<baseline> $h
done
# Marks prefixed with "+" are already in baseline (good — fix merged),
# "-" means not in baseline (expected for feature commits).
```

### Step 4: Push, create PRs, and watch CI

#### 4a. Push all branches

Push each fix branch and the feature branch to remote. Do NOT merge locally — all merging happens through PR on GitHub.

```bash
git push -u origin fix/<scope>/<topic>
# repeat for each fix branch
git push -u origin <feature-branch>
```

#### 4b. Create PRs via `gh` CLI

For each fix branch, create a PR targeting the baseline. The `gh` CLI is preferred over manual GitHub UI — it produces a consistent compare link and can fill the body from the commit message.

```bash
gh pr create \
  --repo <owner>/<repo> \
  --base <baseline-branch> \
  --head fix/<scope>/<topic> \
  --title "<commit subject line>" \
  --body "<commit body or auto-generated>"
```

For the feature branch, create the PR **after** all fix PRs have merged and the feature branch has been rebased onto the updated baseline (see Step 4e). If the feature PR is created before fix PRs merge, it will show the cherry-picked commits as part of the diff — which is noisy but not blocking; reviewers can still see it's only F+D commits once the fix PRs merge and the branch is rebased.

The PR compare link is also available without creating a PR:
```
https://github.com/<owner>/<repo>/compare/<baseline>...<branch>
```

#### 4c. Watch CI checks

After creating (or pushing to) a PR, CI workflows trigger automatically. Use `gh pr checks` to poll status:

```bash
gh pr checks <PR-number> --repo <owner>/<repo>
```

CI typically takes 3–10 minutes. Poll with a sleep loop:

```bash
# Wait for CI to finish (poll every 60s, max 15 min)
while true; do
  status=$(gh pr checks <PR-number> --repo <owner>/<repo> 2>&1)
  echo "$status"
  if echo "$status" | grep -qE "fail|pass" && ! echo "$status" | grep -q "pending"; then
    break
  fi
  sleep 60
done
```

If CI fails, fetch the failed job logs immediately:

```bash
# Get the run ID from the failing check URL, then:
gh run view <run-id> --repo <owner>/<repo> --log-failed 2>&1 | tail -80
```

Common CI failure causes for fix branches:
- **Lint errors**: the squash cherry-pick may have introduced import ordering issues or unused variables. Run `biome check src --write` (console) or `go vet`/`gofmt` (backend) locally, commit the auto-fix, push again.
- **Test failures**: if a fix changes behavior, existing tests may need updating. Read the failure, fix the test, push.
- **Pre-existing baseline lint debt**: sometimes the baseline itself has lint errors that only surface when a PR touches related files (CI runs `biome check` on the whole `src/` directory). These are NOT introduced by the fix — but the PR still blocks on them. The pragmatic answer: fix the baseline lint debt in the same PR with a `chore: fix baseline lint debt` commit, noting it's not from the fix itself.

#### 4d. Merge fix PRs (in any order — they're independent)

Fix PRs don't depend on each other (they touch disjoint files), so merge them in any order. After each merge:

```bash
git fetch origin <baseline>
# verify the baseline moved forward
git log --oneline -3 origin/<baseline>
```

#### 4e. Rebase feature branch and create feature PR

After ALL fix PRs have merged into the baseline:

```bash
git checkout <feature-branch>
git fetch origin <baseline>
git rebase origin/<baseline>
```

During rebase, git detects that the cherry-picked commits' patches are already in the baseline (they arrived via the fix PRs) and auto-skips them. The feature branch now contains only F + D commits. If a commit doesn't auto-skip (rare), manually `git rebase --skip` it — its content is already in the baseline.

Force-push the rebased feature branch:
```bash
git push --force-with-lease origin <feature-branch>
```

Then create the feature PR:
```bash
gh pr create \
  --repo <owner>/<repo> \
  --base <baseline> \
  --head <feature-branch> \
  --title "feat(<scope>): <feature summary>" \
  --body "<feature description, what changed, test plan>"
```

Watch CI on the feature PR the same way as 4c.

## Common pitfalls

### "I already pushed the feature branch to remote"

If you've already pushed the mixed branch to `origin/<feature-branch>`, rebasing to drop commits requires a force-push. This is safe if no one else is basing work off your feature branch (check with the team). Use `--force-with-lease`:

```bash
git push --force-with-lease origin <feature-branch>
```

If others ARE working off it, do not force-push. Instead, create a new clean branch (`<feature-branch>-clean`) and push that, leaving the original as-is. Open the PR from the clean branch.

### "The fix and the feature touch the same file"

If a B-classified fix and an F-classified feature commit both modify the same file (e.g. both touch `service.go`), cherry-picking the fix out and rebasing the feature will likely produce a conflict. Two options:
- If the changes are in different functions/regions, the cherry-pick + rebase will auto-resolve. Verify with a build + test after rebase.
- If they overlap, the fix is probably actually a **D (dependency)** — it only makes sense in the feature's context. Reclassify it as D and keep it on the feature branch. The triage is a judgment call, not a rigid rule.

### "I'm not sure if a commit is B or D"

When uncertain, ask: "If I abandoned this feature branch entirely, would this commit still be valuable on the baseline?" If yes → B. If the commit's value only materializes with the feature → D. When still uncertain, lean toward D (keeping it on the feature branch) — it's safer to over-include in the feature PR than to orphan a fix that depends on feature context.

### "There are too many commits to classify by hand"

For branches with 15+ commits, use `git log` with file summaries to speed up classification:

```bash
git log --oneline --stat origin/<baseline>..HEAD | less
```

Group by directory/module first (all `console/src/...` commits are likely one concern, all `internal/ssh/...` another), then read the actual diffs only for ambiguous cases.

## Decision flowchart

```
commit on feature branch
  │
  ├── is it the work the branch name promises?
  │     yes → F (keep on feature branch)
  │     no  ↓
  │
  ├── would a user on baseline (without the feature) hit this bug?
  │     yes → B (cherry-pick to fix branch, merge first)
  │     no  → D (keep on feature branch — depends on feature context)
  │
  └── multiple commits fixing the same thing?
        squash first, then classify the result
```

## Output

The skill produces:
1. A **triage table** (commit hash → bucket F/B/D + reason) — shown to the user for confirmation before any git surgery.
2. **One or more `fix/<scope>/<topic>` branches** — each containing a single logical fix, ready to PR.
3. **A cleaned feature branch** — containing only F + D commits, rebased on the latest baseline.
4. **A merge order recommendation** — fix PRs first, feature PR last.