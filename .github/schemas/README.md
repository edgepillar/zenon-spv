# Pinned lint configuration schema

The schema is copied without changes from [golangci-lint v2.6.2](https://github.com/golangci/golangci-lint/blob/dc16cf43c85d53f03e00a2f7b93a5e03a1435793/jsonschema/golangci.next.jsonschema.json), commit `dc16cf43c85d53f03e00a2f7b93a5e03a1435793`. Its SHA-256 is `fb4e21238eb335951ed287f36dd46edb56f741fbef22a27c6d89bd697fa7468f`. The versioned v2.6 schema served by the project website was byte-identical when selected.

This component is licensed under GPL-3.0; its upstream license is included in [LICENSE-golangci-lint](LICENSE-golangci-lint). The main repository license is unchanged.

CI checks the pinned digest and runs `golangci-lint config verify --schema .github/schemas/golangci.v2.6.2.jsonschema.json` with golangci-lint v2.6.2. Configuration validation and the unchanged lint run must both pass. The action's implicit website fetch is replaced by this explicit local validation; no schema or lint rules are disabled.
