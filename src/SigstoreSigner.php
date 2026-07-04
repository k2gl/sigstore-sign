<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign;

use K2gl\Dsse\Envelope;
use K2gl\Dsse\Pae;
use K2gl\Dsse\Signature;
use K2gl\RekorClient\RekorClient;
use K2gl\SigstoreBundle\Bundle;
use K2gl\SigstoreBundle\HashAlgorithm;
use K2gl\SigstoreBundle\MessageSignature;

/**
 * The Sigstore signing flow, end to end: sign, log the entry to Rekor, timestamp
 * the signature, and assemble the bundle — so a caller goes from an artifact (or
 * an attestation payload) and a key to a ready `.sigstore.json`.
 *
 * A timestamp authority is optional but usually needed: a Rekor v2 entry carries
 * no integrated time, so without a trusted timestamp the resulting bundle has no
 * signing time and will not verify. Supply a {@see TsaClient} when signing
 * against Rekor v2.
 *
 * This covers the keyful path (you bring the key, and its certificate or a
 * public-key hint). Keyless signing (Fulcio + OIDC) is a later addition.
 */
final class SigstoreSigner
{
    public function __construct(
        private readonly RekorClient $rekor,
        private readonly ?TsaClient $tsa = null,
    ) {}

    /**
     * Sign an artifact and produce a message-signature bundle. The signature is
     * over the artifact's SHA-256 digest (the message-signature convention);
     * use {@see signAttestation()} with a DSSE payload for Ed25519 keys.
     */
    public function signArtifact(string $artifact, SigningKey $key): Bundle
    {
        $digest = hash('sha256', $artifact, true);
        $signature = $key->sign($artifact);

        $entry = $this->rekor->submitHashedRekord($digest, $signature, $key->rekorVerifier());

        return Bundle::forMessageSignature(
            new MessageSignature(HashAlgorithm::SHA2_256, $digest, $signature),
            $key->bundleIdentity(),
            [$entry],
            $this->timestamps($signature),
        );
    }

    /**
     * Sign an attestation payload (e.g. an in-toto Statement, serialised) as a
     * DSSE envelope and produce a DSSE bundle. The Rekor entry binds the digest
     * of the DSSE PAE, as Rekor v2 records DSSE attestations.
     */
    public function signAttestation(string $payload, string $payloadType, SigningKey $key): Bundle
    {
        $pae = Pae::encode($payloadType, $payload);
        $signature = $key->sign($pae);

        $envelope = new Envelope($payload, $payloadType, [new Signature($signature, $key->keyId())]);
        $entry = $this->rekor->submitHashedRekord(hash('sha256', $pae, true), $signature, $key->rekorVerifier());

        return Bundle::forDsse(
            $envelope,
            $key->bundleIdentity(),
            [$entry],
            $this->timestamps($signature),
        );
    }

    /** @return list<string> */
    private function timestamps(string $signature): array
    {
        return $this->tsa === null ? [] : [$this->tsa->timestamp($signature)];
    }
}
