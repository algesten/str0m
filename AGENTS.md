# Declaration order

Order constants, types, functions, and other declarations depth-first by first
mention, starting with the entry point. When adding a declaration to existing
code, place it where it belongs in that order.

# Control flow

Keep nesting shallow. Prefer early returns for guard conditions and `let ... else`
when a failed pattern match should exit the current path. Extract a distinct
step into a small helper function when doing so simplifies a nested block.

When an `if` condition would wrap across lines, extract its predicates into
descriptive local `let` bindings so the condition fits on one line. Also use
local bindings when naming an intermediate value makes its purpose clearer.

# Changelog entries

Before merging a PR with a user-visible change, add an entry under `# Unreleased`
in `CHANGELOG.md`. Read several recent entries before drafting or revising one
and match their length and level of detail.

Keep each entry on a single unwrapped line of at most 90 characters, counting
everything from the leading spaces through the PR number. Shorten the wording
until it fits. Start with two spaces, `*`, and a space. Use an
imperative verb to describe what changes for the user. Wrap code identifiers in
backticks and end with the PR number in the form `#1234`. For a breaking change,
put `(breaking)` immediately before the PR number.

```markdown
  * Replace `set_desired_bitrate` with `set_bitrate(minimum, desired)` (breaking) #1109
```

# Pull request titles and descriptions

Use the PR title as the squash commit subject. Write a concise, imperative
title that names the change. Use the PR description as the commit body, with
a single `## Summary` section explaining what the whole PR changes and why.

Write for someone reading `git log` after the merge. Omit temporary status,
review history, superseded approaches, and plans for future work. Keep test
plans, generated-by lines, and co-author trailers out of the PR description.
Before merging, check the title and description against the final diff and
revise both to reflect what will land.
