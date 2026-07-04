<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign;

use JsonException;
use K2gl\SigstoreSign\Exception\FulcioException;
use K2gl\SigstoreSign\Internal\Pem;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * A client for Fulcio, the Sigstore certificate authority. Given an OIDC
 * identity token, an ephemeral public key and a proof that the caller holds the
 * matching private key, Fulcio returns a short-lived certificate binding the key
 * to the identity — the keyless-signing certificate.
 *
 * Transport is any PSR-18 client the caller supplies; the Fulcio URL is required
 * (Sigstore's public-good instance is fulcio.sigstore.dev).
 *
 * @see https://github.com/sigstore/fulcio/blob/main/fulcio.proto
 */
final class FulcioClient
{
    private readonly string $baseUrl;

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        string $baseUrl,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Request a signing certificate. Returns the leaf certificate as raw DER.
     *
     * @param string $oidcToken         the OIDC identity token
     * @param string $publicKeyPem      PEM of the ephemeral public key
     * @param string $proofOfPossession raw signature over the token's `sub` claim
     * @param string $algorithm         Fulcio PublicKeyAlgorithm ("ECDSA", "RSA_PSS", "ED25519")
     */
    public function requestCertificate(
        string $oidcToken,
        string $publicKeyPem,
        string $proofOfPossession,
        string $algorithm = 'ECDSA',
    ): string {
        $body = [
            'credentials' => ['oidcIdentityToken' => $oidcToken],
            'publicKeyRequest' => [
                'publicKey' => ['algorithm' => $algorithm, 'content' => $publicKeyPem],
                'proofOfPossession' => base64_encode($proofOfPossession),
            ],
        ];

        try {
            $json = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new FulcioException('Could not encode the Fulcio request: ' . $e->getMessage(), previous: $e);
        }

        $request = $this->requestFactory->createRequest('POST', $this->baseUrl . '/api/v2/signingCert')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($json));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new FulcioException('Fulcio request failed: ' . $e->getMessage(), previous: $e);
        }
        $payload = (string) $response->getBody();

        if ($response->getStatusCode() !== 200 && $response->getStatusCode() !== 201) {
            throw new FulcioException(sprintf(
                'Fulcio returned HTTP %d: %s',
                $response->getStatusCode(),
                trim($payload) === '' ? '(empty body)' : trim($payload),
            ));
        }

        return Pem::toDer($this->leafPem($payload));
    }

    private function leafPem(string $payload): string
    {
        try {
            $decoded = json_decode($payload, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new FulcioException('Fulcio response was not valid JSON: ' . $e->getMessage());
        }

        if (! is_array($decoded)) {
            throw new FulcioException('Fulcio response was not a JSON object.');
        }
        $wrapper = $decoded['signedCertificateEmbeddedSct'] ?? $decoded['signedCertificateDetachedSct'] ?? null;

        if (! is_array($wrapper) || ! is_array($wrapper['chain'] ?? null)) {
            throw new FulcioException('Fulcio response has no certificate chain.');
        }
        $certificates = $wrapper['chain']['certificates'] ?? null;

        if (! is_array($certificates) || ! isset($certificates[0]) || ! is_string($certificates[0])) {
            throw new FulcioException('Fulcio certificate chain is empty.');
        }

        return $certificates[0];
    }
}
