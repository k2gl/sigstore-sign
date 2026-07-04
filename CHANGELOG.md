# Changelog

## 1.1.0

- **Keyless signing** — sign in CI with no long-lived key:
  - **`AmbientCredentials`** reads the OIDC identity token from the environment:
    `githubActions()` exchanges the runner's request token for a signing-audience token,
    `gitlabCi()` reads a configured id_token variable.
  - **`FulcioClient`** requests a signing certificate from Fulcio
    (`POST /api/v2/signingCert`), given the token, an ephemeral public key and a proof of
    possession.
  - **`FulcioSigningKey::create()`** ties it together: generates an ephemeral P-256 key,
    proves possession by signing the token's `sub`, and returns a `SigningKey` bound to the
    issued certificate — the same type keyful signing uses, so `SigstoreSigner` is unchanged.
  - New `FulcioException` for the credential/certificate step.

## 1.0.0

First public release. The Sigstore signing flow end to end, keyful.

- **`SigstoreSigner`** — orchestrates sign → Rekor → timestamp → bundle:
  - `signArtifact()` signs an artifact (over its SHA-256 digest) and returns a
    message-signature bundle.
  - `signAttestation()` wraps a payload in a DSSE envelope, signs the PAE, and returns a
    DSSE bundle. The Rekor entry binds the PAE digest (Rekor v2 records DSSE this way).
- **`SigningKey`** — holds the private half (a `k2gl/dsse` signer) and the public half in
  the two shapes the flow needs, so the private key, the Rekor verifier and the bundle
  identity can never drift apart: `publicKey()` (a key-based identity with a hint) or
  `certificate()` (a Fulcio certificate).
- **`TsaClient`** — an RFC 3161 timestamp-authority client (PSR-18). A Rekor v2 entry has no
  integrated time, so a trusted timestamp is what gives the bundle a verifiable signing
  time; supply one when signing against Rekor v2.
- Builds on `k2gl/dsse`, `k2gl/rekor-client` and `k2gl/sigstore-bundle`; transport is any
  PSR-18 client the caller supplies. Fail-closed: `SigningException` and `TimestampException`.
- Scope is the **keyful** path. Keyless signing (Fulcio + OIDC ambient credentials) is a
  later addition.
