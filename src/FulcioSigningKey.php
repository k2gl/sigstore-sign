<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign;

use K2gl\Dsse\EcdsaP256Signer;
use K2gl\RekorClient\KeyDetails;
use K2gl\SigstoreSign\Exception\FulcioException;
use K2gl\SigstoreSign\Internal\Jwt;

/**
 * Keyless signing key material. Generates an ephemeral P-256 key, proves
 * possession of it to Fulcio against an OIDC identity token, and returns a
 * {@see SigningKey} bound to the short-lived certificate Fulcio issues — ready
 * for {@see SigstoreSigner}. The private key never leaves the process and is
 * meant to be discarded after signing.
 */
final class FulcioSigningKey
{
    /**
     * Obtain a keyless signing key: mint an ephemeral key, get a Fulcio
     * certificate for it, and wrap both as a {@see SigningKey}.
     *
     * @param string $oidcToken the OIDC identity token (see {@see AmbientCredentials})
     */
    public static function create(FulcioClient $fulcio, string $oidcToken): SigningKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        if ($key === false) {
            throw new FulcioException('Could not generate an ephemeral signing key.');
        }
        openssl_pkey_export($key, $privatePem);
        $details = openssl_pkey_get_details($key);

        if ($details === false || ! is_string($details['key'] ?? null)) {
            throw new FulcioException('Could not read the ephemeral public key.');
        }
        $publicKeyPem = $details['key'];

        // Prove possession by signing the token's subject. Fulcio expects an
        // ASN.1 DER ECDSA signature here (not the raw r||s a DSSE signer emits).
        $proof = '';

        if (openssl_sign(Jwt::claim($oidcToken, 'sub'), $proof, $key, OPENSSL_ALGO_SHA256) === false) {
            throw new FulcioException('Could not sign the proof of possession.');
        }
        $certificateDer = $fulcio->requestCertificate($oidcToken, $publicKeyPem, $proof, 'ECDSA');

        return SigningKey::certificate(
            EcdsaP256Signer::fromPem($privatePem, null),
            $certificateDer,
            KeyDetails::PKIX_ECDSA_P256_SHA_256,
        );
    }
}
