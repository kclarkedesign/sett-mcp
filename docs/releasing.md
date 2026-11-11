# Releasing Sett

The version comes from the git tag, so a release needs no version-bump pull request.

1. Merge the pull requests that should go out. Check CI is green on `main`.
2. On GitHub: **Releases, Draft a new release**.
3. **Choose a tag:** type the next version with a `v` (`v0.3.3`), choose *Create new tag on publish*, target `main`.
4. **Generate release notes.** GitHub lists the merged pull requests, grouped by the labels added automatically from the files each one changed (Remote deploy, Clients and install, Guardrails, Docs, Maintenance). Write a sentence or two at the top saying what the release is for.
5. **Publish release.** The *Publish to PyPI* workflow builds `sett-mcp` at the tag's version, checks the two match, and publishes it. `uvx sett-mcp new` then uses this release's template.

Version numbers: the last number for fixes and small additions (0.3.2 to 0.3.3), the middle one for a notable new capability (0.3 to 0.4).

If a release was created from the wrong commit, delete the release and its tag (Code, Tags), then create it again. A tag that never reached PyPI can be reused.
