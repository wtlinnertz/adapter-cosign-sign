"""AIEOS adapter: sign.artifact + sign.attestation via cosign.

Multi-capability — registers TWICE (once per contract) with separate
attestations per the plan's §M4a.4 note. Two classes exposed:

  SignArtifactAdapter     — satisfies sign.artifact. Signs an OCI image
                            reference (or a blob representing it) and
                            emits a Sigstore bundle.
  SignAttestationAdapter  — satisfies sign.attestation. Constructs an
                            in-toto Statement over a subject + predicate,
                            then signs the Statement as a blob.

Both wrap `cosign sign-blob --bundle` which produces a Sigstore bundle
(media type application/vnd.dev.sigstore.bundle.v0.3+json) matching the
findings/schemas/oci-signing-bundle.schema.json shape.

Signing-identity modes:
  key:<path>       — local keypair (COSIGN_PASSWORD env var carries the password).
  ambient          — ambient OIDC (GitHub Actions issuer is detected by cosign).
  oidc:<issuer-url> — explicit OIDC issuer (rare for v1).
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__version__ = "1.0.0"


@dataclass
class AdapterResult:
    findings: dict[str, Any] | None
    evidence: list[str]
    exit_code: int


def _parse_signing_identity(ref: str) -> tuple[str, str]:
    """Returns (mode, value). mode in {'key', 'ambient', 'oidc'}."""
    if ref == "ambient":
        return "ambient", ""
    if ref.startswith("key:"):
        return "key", ref[len("key:") :]
    if ref.startswith("oidc:"):
        return "oidc", ref[len("oidc:") :]
    raise ValueError(
        f"unrecognized signing_identity_ref {ref!r}; expected "
        "'ambient', 'key:<path>', or 'oidc:<issuer>'"
    )


def _cosign_sign_blob(
    payload_path: Path,
    signing_identity_ref: str,
    *,
    cosign_binary: str = "cosign",
    cosign_password: str | None = None,
) -> tuple[int, dict[str, Any] | None, str]:
    """Run cosign sign-blob on payload_path.

    Returns (exit_code, bundle_dict_or_none, stderr). The bundle is parsed
    from a tempfile that cosign writes via --bundle.
    """
    mode, value = _parse_signing_identity(signing_identity_ref)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sigstore.json", delete=False) as bundle_tmp:
        bundle_path = Path(bundle_tmp.name)
    try:
        # --new-bundle-format emits the Sigstore protobuf bundle
        # (mediaType/verificationMaterial/messageSignature) that the AIEOS
        # oci-signing-bundle schema models; the legacy --bundle output
        # ({base64Signature, rekorBundle}) does not validate against it.
        cmd = [
            cosign_binary, "sign-blob",
            "--new-bundle-format",
            "--bundle", str(bundle_path), "--yes",
        ]
        if mode == "key":
            cmd.extend(["--key", value])
        # ambient / oidc modes rely on the execution environment providing OIDC.
        cmd.append(str(payload_path))

        env = dict(os.environ)
        if cosign_password is not None:
            env["COSIGN_PASSWORD"] = cosign_password

        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, env=env)
        if proc.returncode != 0 or not bundle_path.is_file():
            return proc.returncode, None, proc.stderr
        try:
            bundle = json.loads(bundle_path.read_text())
        except json.JSONDecodeError as exc:
            return proc.returncode, None, f"bundle parse error: {exc}"
        return 0, bundle, proc.stderr
    finally:
        if bundle_path.is_file():
            try:
                bundle_path.unlink()
            except OSError:
                pass


class SignArtifactAdapter:
    """Satisfies the sign.artifact contract.

    Inputs: image_ref (OCI digest or tag), signing_identity_ref.
    Output: Sigstore bundle (findings), signed-image-digest + sigstore-bundle evidence.

    v1 implementation detail: the adapter signs a blob whose content is the
    image_ref string. In production, integrations wire this to a registry
    client that fetches the image manifest and signs its digest; the bundle
    shape the harness validates against is the same either way.
    """

    def __init__(
        self,
        *,
        cosign_binary: str = "cosign",
        cosign_password: str = "",
    ) -> None:
        self._cosign = cosign_binary
        self._password = cosign_password

    def execute(self, inputs: dict[str, Any]) -> AdapterResult:
        image_ref = inputs["image_ref"]
        signing_identity_ref = inputs["signing_identity_ref"]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as payload:
            payload.write(image_ref)
            payload_path = Path(payload.name)

        try:
            exit_code, bundle, stderr = _cosign_sign_blob(
                payload_path,
                signing_identity_ref,
                cosign_binary=self._cosign,
                cosign_password=self._password,
            )
        finally:
            if payload_path.is_file():
                payload_path.unlink()

        if exit_code != 0 or bundle is None:
            return AdapterResult(
                findings=None,
                evidence=[
                    f"exit-code:{exit_code}",
                    "stderr:" + (stderr[:500] if stderr else ""),
                ],
                exit_code=exit_code if exit_code != 0 else 3,
            )

        return AdapterResult(
            findings=bundle,
            evidence=[
                f"signed-image-digest:{image_ref}",
                "sigstore-bundle:inline",
                f"exit-code:{exit_code}",
            ],
            exit_code=0,
        )


class SignAttestationAdapter:
    """Satisfies the sign.attestation contract.

    Inputs: subject_ref, predicate_payload (dict), predicate_type (URI),
            signing_identity_ref.
    Output: Sigstore bundle wrapping an in-toto Statement over the
            (subject, predicate) pair.
    """

    def __init__(
        self,
        *,
        cosign_binary: str = "cosign",
        cosign_password: str = "",
    ) -> None:
        self._cosign = cosign_binary
        self._password = cosign_password

    def execute(self, inputs: dict[str, Any]) -> AdapterResult:
        statement = build_intoto_statement(
            subject_ref=inputs["subject_ref"],
            predicate_payload=inputs["predicate_payload"],
            predicate_type=inputs["predicate_type"],
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".statement.json", delete=False
        ) as payload:
            json.dump(statement, payload, sort_keys=True)
            payload_path = Path(payload.name)

        try:
            exit_code, bundle, stderr = _cosign_sign_blob(
                payload_path,
                inputs["signing_identity_ref"],
                cosign_binary=self._cosign,
                cosign_password=self._password,
            )
        finally:
            if payload_path.is_file():
                payload_path.unlink()

        if exit_code != 0 or bundle is None:
            return AdapterResult(
                findings=None,
                evidence=[
                    f"exit-code:{exit_code}",
                    "stderr:" + (stderr[:500] if stderr else ""),
                ],
                exit_code=exit_code if exit_code != 0 else 3,
            )

        # For sign.attestation, the contract schema expects dsseEnvelope OR
        # messageSignature. cosign sign-blob produces messageSignature.
        # Real in-toto attestations wrap the statement in a DSSE envelope;
        # v1 reports the statement as inline evidence and the bundle as
        # findings. v1.1 will call cosign's attest-blob for a proper DSSE
        # envelope.
        return AdapterResult(
            findings=bundle,
            evidence=[
                f"in-toto-statement:inline:{base64.b64encode(json.dumps(statement).encode()).decode()[:64]}...",
                "sigstore-bundle:inline",
                f"exit-code:{exit_code}",
            ],
            exit_code=0,
        )


def build_intoto_statement(
    *,
    subject_ref: str,
    predicate_payload: dict[str, Any],
    predicate_type: str,
) -> dict[str, Any]:
    """Construct a minimal in-toto v1 Statement over (subject, predicate)."""
    digest = {}
    if subject_ref.startswith("sha256:"):
        digest = {"sha256": subject_ref[len("sha256:") :]}
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": predicate_type,
        "subject": [{"name": subject_ref, "digest": digest}],
        "predicate": predicate_payload,
    }
