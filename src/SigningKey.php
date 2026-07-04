<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign;

use K2gl\Dsse\Signer;
use K2gl\RekorClient\KeyDetails;
use K2gl\RekorClient\Verifier;
use K2gl\SigstoreBundle\SigningIdentity;
use K2gl\SigstoreSign\Exception\SigningException;
use K2gl\SigstoreSign\Internal\Der;

/**
 * A signing key as this package needs it: the private half (a DSSE {@see Signer}
 * that produces signatures) plus the public half in the two shapes the rest of
 * the flow needs — the {@see Verifier} that goes into the Rekor submission and
 * the {@see SigningIdentity} that goes into the bundle.
 *
 * Build it once from your key material and hand it to {@see SigstoreSigner};
 * everything downstream reads from it, so the private key, the Rekor verifier
 * and the bundle identity can never drift apart.
 */
final class SigningKey
{
    private function __construct(
        private readonly Signer $signer,
        private readonly Verifier $verifier,
        private readonly SigningIdentity $identity,
        private readonly KeyDetails $keyDetails,
    ) {}

    /**
     * A key-based identity: the public key travels out of band, the bundle names
     * it by hint (the cosign convention is the hex SHA-256 of the DER key).
     *
     * @param string $publicKeyDer raw DER SubjectPublicKeyInfo of the public key
     */
    public static function publicKey(Signer $signer, string $publicKeyDer, KeyDetails $keyDetails, string $hint): self
    {
        if ($publicKeyDer === '') {
            throw new SigningException('Public key DER must not be empty.');
        }

        if ($hint === '') {
            throw new SigningException('Public-key hint must not be empty.');
        }

        return new self(
            $signer,
            Verifier::publicKey($publicKeyDer, $keyDetails),
            SigningIdentity::publicKey($hint),
            $keyDetails,
        );
    }

    /**
     * A certificate identity: the Fulcio (or other X.509) signing certificate
     * travels in the bundle.
     *
     * @param string $certificateDer raw DER of the signing certificate
     */
    public static function certificate(Signer $signer, string $certificateDer, KeyDetails $keyDetails): self
    {
        if ($certificateDer === '') {
            throw new SigningException('Certificate DER must not be empty.');
        }

        return new self(
            $signer,
            Verifier::certificate($certificateDer, $keyDetails),
            SigningIdentity::certificate($certificateDer),
            $keyDetails,
        );
    }

    /**
     * Sign a message (the PAE for an attestation, the artifact for a signature).
     * Sigstore carries ECDSA signatures as ASN.1 DER, but a DSSE signer emits the
     * raw r||s form, so ECDSA signatures are re-encoded to DER here.
     */
    public function sign(string $message): string
    {
        $signature = $this->signer->sign($message);

        return $this->isEcdsa() ? $this->ecdsaRawToDer($signature) : $signature;
    }

    private function isEcdsa(): bool
    {
        return in_array($this->keyDetails, [
            KeyDetails::PKIX_ECDSA_P256_SHA_256,
            KeyDetails::PKIX_ECDSA_P384_SHA_384,
            KeyDetails::PKIX_ECDSA_P521_SHA_512,
        ], true);
    }

    private function ecdsaRawToDer(string $raw): string
    {
        $half = intdiv(strlen($raw), 2);

        return Der::sequence(
            Der::integerFromBytes(substr($raw, 0, $half)),
            Der::integerFromBytes(substr($raw, $half)),
        );
    }

    /** The key id the DSSE signer reports, if any (goes into the envelope signature). */
    public function keyId(): ?string
    {
        return $this->signer->keyId();
    }

    public function rekorVerifier(): Verifier
    {
        return $this->verifier;
    }

    public function bundleIdentity(): SigningIdentity
    {
        return $this->identity;
    }
}
