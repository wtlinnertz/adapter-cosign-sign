# AIEOS Adapter — sign.artifact + sign.attestation via cosign

Multi-capability adapter; two classes (SignArtifactAdapter +
SignAttestationAdapter), one package.

## Contracts

- sign.artifact @ 1.0.0 — aieos-governance-foundation/contracts/sign.artifact.contract.yaml
- sign.attestation @ 1.0.0 — aieos-governance-foundation/contracts/sign.attestation.contract.yaml

Per §M4a.4: register twice, separate attestation per claim.

## Implementation plan

Read the M4 section of `~/second-brain/AIEOS Spec-Driven CI-CD Implementation Plan.md`.

## Requirements

- Wrap cosign deterministically where possible (modulo Rekor timestamps).
- Accept the contract's required_inputs for each capability.
- Emit Sigstore bundles matching findings/schemas/oci-signing-bundle.schema.json.
- Ship TWO passing conformance attestations (one per contract).
- Document normalization decisions in MAPPING.md.

## Python conventions

- Type hints on public functions.
- `ruff` for linting.
- Tests in AAA shape. Integration tests skip if cosign is not on $PATH.
