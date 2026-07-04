<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign;

use JsonException;
use K2gl\SigstoreSign\Exception\FulcioException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * Reads an OIDC identity token from the ambient CI environment, so keyless
 * signing needs no configured secret. On GitHub Actions it exchanges the
 * runner's request token for a signing-audience token; on GitLab CI it reads the
 * id_token the pipeline was configured to inject.
 */
final class AmbientCredentials
{
    /**
     * The OIDC token from GitHub Actions. Needs `id-token: write` permission on
     * the job. Reads `ACTIONS_ID_TOKEN_REQUEST_URL` / `..._TOKEN` and calls the
     * token endpoint for the given audience.
     */
    public static function githubActions(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        string $audience = 'sigstore',
    ): string {
        $url = getenv('ACTIONS_ID_TOKEN_REQUEST_URL');
        $token = getenv('ACTIONS_ID_TOKEN_REQUEST_TOKEN');

        if ($url === false || $url === '' || $token === false || $token === '') {
            throw new FulcioException(
                'Not running under GitHub Actions with id-token permission '
                . '(ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN are not set).'
            );
        }
        $separator = str_contains($url, '?') ? '&' : '?';
        $request = $requestFactory->createRequest('GET', $url . $separator . 'audience=' . rawurlencode($audience))
            ->withHeader('Authorization', 'Bearer ' . $token)
            ->withHeader('Accept', 'application/json');

        try {
            $response = $httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new FulcioException('Could not fetch the GitHub Actions OIDC token: ' . $e->getMessage(), previous: $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw new FulcioException(sprintf('GitHub Actions token endpoint returned HTTP %d.', $response->getStatusCode()));
        }

        try {
            $decoded = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new FulcioException('GitHub Actions token response was not valid JSON: ' . $e->getMessage());
        }

        if (! is_array($decoded) || ! isset($decoded['value']) || ! is_string($decoded['value']) || $decoded['value'] === '') {
            throw new FulcioException('GitHub Actions token response has no "value".');
        }

        return $decoded['value'];
    }

    /**
     * The OIDC token from a GitLab CI id_token, read from an environment variable
     * (by convention `SIGSTORE_ID_TOKEN`; pass another name if you configured one).
     */
    public static function gitlabCi(string $variable = 'SIGSTORE_ID_TOKEN'): string
    {
        $token = getenv($variable);

        if ($token === false || $token === '') {
            throw new FulcioException(sprintf('GitLab CI id_token variable "%s" is not set.', $variable));
        }

        return $token;
    }
}
