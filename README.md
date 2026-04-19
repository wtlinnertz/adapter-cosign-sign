# adapter-cosign-sign

AIEOS multi-capability adapter satisfying **both** `sign.artifact` and
`sign.attestation` via cosign.

## Contracts (two — registers twice)

- `sign.artifact` at contract version 1.0.0 — wraps `cosign sign-blob`
  to sign an OCI image reference and emit a Sigstore bundle.
- `sign.attestation` at contract version 1.0.0 — constructs an in-toto
  Statement over (subject, predicate) and signs it; emits the same
  Sigstore bundle format.

Per the plan's §M4a.4 note, multi-capability adapters register per
contract with a separate conformance attestation per claim. Do NOT
register a single entry claiming both.

## Prerequisites

- `cosign` v2.0.0+ installed on `$PATH`. v3.0.6 verified.
- For local testing: a keypair via `cosign generate-key-pair` (password
  passed through the `cosign_password` constructor argument; empty for
  unencrypted test keys).
- For CI signing: ambient OIDC via `sigstore/cosign-installer` + `id-token: write`.

## Signing-identity modes

| Mode | Format | Use |
|---|---|---|
| Local keypair | `key:/path/to/cosign.key` | Development, tests |
| Ambient OIDC | `ambient` | GitHub Actions, GitLab CI |
| Explicit issuer | `oidc:<issuer-url>` | Non-default OIDC providers |

## Development

```bash
pip install -e '.[dev]'
pytest
```

Tests skip gracefully if cosign is not on `$PATH`.

## License

MIT.
