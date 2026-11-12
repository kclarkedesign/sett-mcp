## Why
<!-- One short paragraph. Its first sentence is the summary: a reader who stops there should know what this fixes and whether it affects them. -->

**Release steps:** None.
<!-- Replace "None." with anything needed outside this diff (a label the labeler uses, a repo or PyPI setting, a release to cut): order relative to merge, and whether it's done. Merging doesn't publish; publishing a GitHub release does (publish.yml). Keep this line either way. -->

<!-- "Closes #N" only for an issue this PR fully resolves; "Related: #N" otherwise; delete if neither. -->

## What changed
- <!-- The smallest useful change. Tables welcome. When relevant, end with "Not in this PR" (and where it's tracked) and "Known limits". -->

## Validation and proof
<!-- 2–4 sentences: what behaviour changed, what existing behaviour is unchanged, and how the test tells broken from fixed. Don't repeat Why or What changed. -->

- [ ] Tests green (___ tests); if the template changed, run on a rendered project (`copier copy`, then `uv run --extra dev pytest`)
- [ ] Bug fix: reverted it and watched a test fail
- [ ] Reached by a real run: a rendered server in a real client (Claude Code, Claude Desktop, Codex), or `sett-mcp check <url>` for deploy changes
- [ ] Codex reviewed the latest commit; each finding fixed, or the maintainer agreed to defer it (linked) or decline it

<!-- [x] = done. "[ ] Pending: …" = not yet. "[ ] Not run: reason" = applicable but skipped or impossible. A box that doesn't apply becomes a plain bullet "N/A: reason", which keeps it out of the PR list's task count. Docs-only PRs: one "N/A: docs only" bullet replaces the first three boxes. Update this section before merging. -->

<details><summary>Background</summary>

<!-- Derivation, review history, dead ends. Delete the block if empty. -->
</details>
