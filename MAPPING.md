# MAPPING — adapter-cosign-sign

Normalization decisions for the sign.artifact + sign.attestation contracts.

## Tool

cosign v2.0.0+ (verified against v3.0.6). Invocation:
`cosign sign-blob --bundle <out> --yes <payload>` with `--key <path>` for
local keypair mode or no `--key` for ambient OIDC.

## Signing-identity modes

Parsed from the `signing_identity_ref` input:

- `ambient` — no cosign flag; cosign detects the OIDC provider from the
  environment (GitHub Actions is supported natively).
- `key:<path>` — `--key <path>`. The password is passed via the
  `cosign_password` constructor argument (empty for test keys).
- `oidc:<issuer>` — currently treated the same as ambient; v1.1 may wire
  cosign's `--identity-token-file` or similar for explicit issuers.

## sign.artifact path

v1 signs a blob whose content is the image_ref string. Production
integrations wire this to a registry client that fetches the image
manifest and signs its digest directly; the Sigstore bundle shape is
identical either way. The adapter's output_schema is satisfied by cosign's
native bundle output.

Evidence: `signed-image-digest:<ref>`, `sigstore-bundle:inline`,
`exit-code:<N>`.

## sign.attestation path

Constructs a minimal in-toto Statement (`_type`,`predicateType`, `subject`,
`predicate`) and serializes it to a tempfile before signing via sign-blob.
Production v1.1 will migrate to `cosign attest-blob` which wraps the
payload in a DSSE envelope end-to-end; the current path produces a
messageSignature bundle, which satisfies the v1 findings schema's
`oneOf messageSignature | dsseEnvelope` discriminator.

Evidence: `in-toto-statement:inline:<base64-first64>`, `sigstore-bundle:inline`,
`exit-code:<N>`.

## Determinism

cosign signing is non-deterministic because:

- The Sigstore bundle embeds a Rekor inclusion promise with a timestamp.
- The signature itself is deterministic w.r.t. the payload + key, but the
  bundle metadata varies.

This is acceptable — the bundle's purpose is attestation, not
reproducibility. The conformance suite's tolerances allow the bundle's
variable metadata to differ between runs.

## Future (v1.1)

- Switch sign.attestation to `cosign attest-blob` for proper DSSE wrapping.
- Explicit OIDC issuer flags (`--identity-token-file`, `--oidc-issuer`).
- Offline verification support in unit tests.
