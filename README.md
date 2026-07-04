# Sign with Sigstore from PHP

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/sigstore-sign/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/sigstore-sign/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/sigstore-sign?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/sigstore-sign)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-level%209-2a5ea7?logo=php&logoColor=white)](https://phpstan.org)
[![License](https://img.shields.io/packagist/l/k2gl/sigstore-sign?color=yellowgreen)](https://packagist.org/packages/k2gl/sigstore-sign)

The Sigstore signing flow, end to end, in PHP: **sign** an artifact or an attestation,
**log** the entry to a Rekor v2 transparency log, **timestamp** the signature, and
**assemble** the `.sigstore.json` bundle — the emit counterpart to
[`k2gl/sigstore-verify`](https://github.com/k2gl/sigstore-verify).

It ties the family together: [`k2gl/dsse`](https://github.com/k2gl/dsse) signs,
[`k2gl/rekor-client`](https://github.com/k2gl/rekor-client) logs,
[`k2gl/sigstore-bundle`](https://github.com/k2gl/sigstore-bundle) is emitted. This release
covers **keyful** signing (you bring the key and its certificate or a public-key hint);
keyless signing via Fulcio + OIDC is a later addition.

## Requirements

- PHP 8.1+
- A PSR-18 HTTP client and PSR-17 factory (for Rekor and the timestamp authority)
- `k2gl/dsse`, `k2gl/rekor-client`, `k2gl/sigstore-bundle`

## Installation

```bash
composer require k2gl/sigstore-sign
```

## Usage

```php
use K2gl\Dsse\EcdsaP256Signer;
use K2gl\RekorClient\{RekorClient, KeyDetails};
use K2gl\SigstoreSign\{SigstoreSigner, SigningKey, TsaClient};

$rekor = new RekorClient($psr18, $psr17, $psr17, 'https://rekor.sigstore.dev');
$tsa   = new TsaClient($psr18, $psr17, $psr17, 'https://timestamp.sigstore.dev');
$signer = new SigstoreSigner($rekor, $tsa);

// The key: a DSSE signer for the private half, plus the public half — here a
// public-key hint (or use SigningKey::certificate() with a Fulcio leaf).
$key = SigningKey::publicKey(
    signer:     EcdsaP256Signer::fromPem(file_get_contents('signing-key.pem'), null),
    publicKeyDer: $publicKeyDer,
    keyDetails: KeyDetails::PKIX_ECDSA_P256_SHA_256,
    hint:       $hexSha256OfThePublicKey,
);

// Sign an artifact → a message-signature bundle.
$bundleJson = $signer->signArtifact(file_get_contents('release.tar.gz'), $key)->toJson();

// …or sign an attestation payload (e.g. an in-toto Statement) → a DSSE bundle.
$bundleJson = $signer->signAttestation($statementJson, 'application/vnd.in-toto+json', $key)->toJson();
```

### Why the timestamp authority matters

A Rekor v2 entry has no integrated time, so a bundle needs a trusted RFC 3161 timestamp to
have a verifiable signing time. Pass a `TsaClient` (Sigstore's public-good TSA is
`timestamp.sigstore.dev`) when signing against Rekor v2 — without it, the bundle logs and
assembles but will not verify for lack of a time source.

### What gets signed

- **Artifact** — the signature is over the artifact's SHA-256 digest (the message-signature
  convention). Use an attestation for Ed25519 keys, which the message-signature path does not
  cover on the verify side.
- **Attestation** — the payload is wrapped in a DSSE envelope and the signature is over the
  PAE; the Rekor entry binds the PAE digest, as Rekor v2 records DSSE attestations.

## Errors

Everything thrown implements `K2gl\SigstoreSign\Exception\SigstoreSignException`:
`SigningException` (the signing flow) and `TimestampException` (the timestamp authority).

## Pull requests are always welcome
[Collaborate with pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request)
