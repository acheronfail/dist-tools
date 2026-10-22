# Credentials

The CLI reads credential JSON from stdin.

Requires Python 3, OpenSSL with `pkey -check`, and authenticated `gh` for GitHub
writes. Older PKCS12 exports use OpenSSL's legacy provider when needed.

## JSON fields

All values are strings. Required fields:

| Field                          | Value                                                                     |
| ------------------------------ | ------------------------------------------------------------------------- |
| `MACOS_CODE_SIGN_P12_BASE64`   | Base64-encoded Developer ID Application PKCS12, including its private key |
| `MACOS_CODE_SIGN_P12_PASSWORD` | PKCS12 password                                                           |
| `APPLE_TEAM_ID`                | Certificate's ten-character team ID                                       |
| `APPLE_NOTARY_AUTH_MODE`       | One mode below                                                            |

Include only the selected mode's additional fields:

| Mode             | Fields                                                                   |
| ---------------- | ------------------------------------------------------------------------ |
| `api-team`       | `APPLE_NOTARY_API_KEY`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`  |
| `api-individual` | `APPLE_NOTARY_API_KEY`, `APPLE_NOTARY_KEY_ID`; omit issuer               |
| `apple-id`       | `APPLE_NOTARY_APPLE_ID`, `APPLE_NOTARY_PASSWORD` (app-specific password) |

`APPLE_NOTARY_API_KEY` is PEM text, not a path or base64. Unknown fields and mixed
or incomplete modes are rejected.

## Inspect and sync

Copy [the example allowlist](../config/repositories.example.json) to
`.local/repositories.json` and replace its entries. `credential-export` below is a
placeholder for your decrypted JSON source:

```sh
credential-export | bin/dist-tools apple credentials inspect
credential-export | bin/dist-tools apple credentials sync \
  --config .local/repositories.json --all --dry-run
credential-export | bin/dist-tools apple credentials sync \
  --config .local/repositories.json --repo example-owner/example-desktop
```

Use repeatable `--repo` flags or `--all`; every target must be allowlisted. Your
GitHub token needs permission to manage Actions secrets and variables there.

Validation checks the certificate, matching private key, team, validity and auth
fields offline. It does not authenticate with Apple. Expired certificates can be
inspected but not synced. Dry runs make **no GitHub calls**.

Sync writes signing and selected auth secrets, plus the `APPLE_NOTARY_AUTH_MODE`
variable. It writes `APPLE_TEAM_ID` as both a secret and compatibility variable;
**use the secret in workflow inputs and environments** so GitHub masks it.
The Action rejects credentials from multiple auth modes.

Updates are not atomic. Review per-target results and rerun after partial failure.
Inactive auth secrets remain available. To roll back, resync the prior encrypted
source and restore the prior Action SHA/auth mapping if needed.

## Health checks

In the tooling repository, sync the same credentials and set:

- `APPLE_CREDENTIAL_HEALTH_ENABLED=true` for weekly certificate checks.
- `APPLE_NOTARY_AUTH_HEALTH_ENABLED=true` to also import the identity on a hosted
  Mac and check `notarytool history`. Individual keys require Xcode 26+.

The [health workflow](../.github/workflows/credential-health.yml) also runs manually.
Checks are read-only. Issues in the tooling repository track
90/60/30-day expiry warnings, invalid credentials and auth failures. Unchanged
problems stay quiet; threshold changes update the issue, recovery closes it and
recurrence reopens it. Reports omit identities, credentials and raw tool logs.

For direct use:

```sh
credential-export | bin/dist-tools apple credentials health
credential-export | bin/dist-tools apple credentials health \
  --issue-repo example-owner/release-tooling
```

Signing-only health needs just the three signing fields. Add `--check-notary`
with full input only on a disposable GitHub-hosted Mac. Serialize invocations
sharing an issue destination. Without issue reporting, detected problems return
nonzero; with reporting, maintained issues return zero, while operational errors
still fail.
