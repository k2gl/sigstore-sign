<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Internal;

use K2gl\SigstoreSign\Exception\FulcioException;

/**
 * Reads a claim out of a JWT's payload without verifying the signature — Fulcio
 * verifies the token, this side only needs the `sub` to build the proof of
 * possession. Decodes the middle base64url segment as JSON.
 *
 * @internal
 */
final class Jwt
{
    public static function claim(string $token, string $claim): string
    {
        $value = self::payload($token)[$claim] ?? null;

        if (! is_string($value) || $value === '') {
            throw new FulcioException(sprintf('OIDC token has no "%s" claim.', $claim));
        }

        return $value;
    }

    /**
     * The value Fulcio signs a proof of possession over: the `email` claim for
     * an email identity, otherwise the `sub` claim (workload identities such as
     * GitHub Actions have no email). Fulcio derives the challenge subject the
     * same way, so signing the wrong one is rejected.
     */
    public static function proofSubject(string $token): string
    {
        $payload = self::payload($token);
        $email = $payload['email'] ?? null;

        if (is_string($email) && $email !== '') {
            return $email;
        }
        $sub = $payload['sub'] ?? null;

        if (! is_string($sub) || $sub === '') {
            throw new FulcioException('OIDC token has neither an "email" nor a "sub" claim.');
        }

        return $sub;
    }

    /** @return array<string, mixed> */
    private static function payload(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new FulcioException('OIDC token is not a well-formed JWT.');
        }
        $payload = base64_decode(strtr($parts[1], '-_', '+/'), true);

        if ($payload === false) {
            throw new FulcioException('OIDC token payload is not valid base64url.');
        }
        $decoded = json_decode($payload, true);

        if (! is_array($decoded)) {
            throw new FulcioException('OIDC token payload is not a JSON object.');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
