# Upstream issues

Bugs found in the sibling libraries this repository builds on — `~/fo/nsh-query` and
`~/fo/nsh-form` — are recorded here. The rule: a bug gets a written-up entry, and any workaround
in this repository's code carries a comment pointing at that entry. A bug is never silently worked
around, and those repositories are never edited from here (they are owned elsewhere and read-only
for this build).

Entries are appended at the join — the coordinator's end-of-build pass collects issues found by
the area agents into this file — so if you hit an upstream bug while building your area, keep the
detail (what you did, what happened, what you expected) available for the join even before an
entry exists.

## Entry template

```
### <short title>
- Found in: <nsh-query | nsh-form>, <crate or package, component>
- What happens: <observed behavior, with the input that triggers it>
- Expected: <what the sibling library's own docs or API imply>
- Hit while: <what this repo was doing when found>
- Workaround here: <what this repo does instead, and where>
- Suggested upstream fix: <one line, or "none — report as-is">
```

## Entries

*(none yet — entries are appended at the join)*
