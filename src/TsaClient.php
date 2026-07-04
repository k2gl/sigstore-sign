<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign;

use K2gl\SigstoreSign\Exception\TimestampException;
use K2gl\SigstoreSign\Internal\Der;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * An RFC 3161 timestamp-authority client. It asks a TSA to timestamp a signature
 * and returns the raw TimeStampToken to embed in a bundle. A Rekor v2 entry has
 * no integrated time, so a trusted timestamp is what gives such a bundle a
 * verifiable signing time.
 *
 * Transport is any PSR-18 client the caller supplies; the TSA URL is required
 * (Sigstore's public-good TSA is timestamp.sigstore.dev).
 */
final class TsaClient
{
    /** id-sha256 (2.16.840.1.101.3.4.2.1). */
    private const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

    private readonly string $url;

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        string $url,
    ) {
        $this->url = $url;
    }

    /**
     * Timestamp a signature and return the raw RFC 3161 TimeStampToken (the value
     * a bundle carries as `signedTimestamp`).
     */
    public function timestamp(string $signature): string
    {
        $request = $this->requestFactory->createRequest('POST', $this->url)
            ->withHeader('Content-Type', 'application/timestamp-query')
            ->withHeader('Accept', 'application/timestamp-reply')
            ->withBody($this->streamFactory->createStream($this->buildRequest($signature)));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new TimestampException('Timestamp request failed: ' . $e->getMessage(), previous: $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw new TimestampException(sprintf('Timestamp authority returned HTTP %d.', $response->getStatusCode()));
        }

        return $this->validated((string) $response->getBody());
    }

    /** Build a TimeStampReq (version 1, SHA-256 imprint of the signature, certReq true). */
    private function buildRequest(string $signature): string
    {
        $imprint = Der::sequence(
            Der::sequence(Der::oid(self::OID_SHA256), Der::null()),
            Der::octetString(hash('sha256', $signature, true)),
        );

        return Der::sequence(
            Der::integer(1),
            $imprint,
            Der::boolean(true),
        );
    }

    /**
     * Check the status is granted and return the whole DER TimeStampResponse.
     * A Sigstore bundle stores the full response (PKIStatusInfo + token), not the
     * token alone, so this returns the bytes as received once validated.
     */
    private function validated(string $response): string
    {
        if ($response === '') {
            throw new TimestampException('Timestamp authority returned an empty response.');
        }
        $outer = Der::read($response, 0);

        if ($outer['tag'] !== 0x30) {
            throw new TimestampException('Timestamp response is not a SEQUENCE.');
        }
        $statusInfo = Der::read($response, $outer['contentStart']);

        if ($statusInfo['tag'] !== 0x30) {
            throw new TimestampException('Timestamp response status is not a SEQUENCE.');
        }
        $status = Der::read($response, $statusInfo['contentStart']);

        if ($status['tag'] !== 0x02 || $status['contentLen'] < 1) {
            throw new TimestampException('Timestamp response has no status.');
        }
        $statusValue = ord($response[$status['contentStart']]);

        // 0 = granted, 1 = grantedWithMods; anything else is a rejection.
        if ($statusValue !== 0 && $statusValue !== 1) {
            throw new TimestampException(sprintf('Timestamp authority rejected the request (status %d).', $statusValue));
        }

        if ($statusInfo['next'] >= $outer['next']) {
            throw new TimestampException('Timestamp response carries no token.');
        }

        return $response;
    }
}
