<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Internal;

use DateTimeImmutable;
use Exception;
use K2gl\SigstoreSign\Exception\InvalidSigningConfigException;

/**
 * Small typed readers over the signing config's JSON, so parsing is total: a
 * missing or wrong-typed field fails as an
 * {@see InvalidSigningConfigException} rather than a stray PHP warning.
 *
 * @internal
 */
final class Json
{
    /** @param array<string, mixed> $data */
    public static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw new InvalidSigningConfigException(sprintf('Expected a non-empty string at "%s".', $key));
        }

        return $value;
    }

    /** @param array<string, mixed> $data */
    public static function int(array $data, string $key): int
    {
        $value = $data[$key] ?? null;

        if (! is_int($value)) {
            throw new InvalidSigningConfigException(sprintf('Expected an integer at "%s".', $key));
        }

        return $value;
    }

    /**
     * @param  array<string, mixed> $data
     * @return list<array<string, mixed>>
     */
    public static function objectList(array $data, string $key): array
    {
        $value = $data[$key] ?? [];

        if (! is_array($value) || ($value !== [] && ! array_is_list($value))) {
            throw new InvalidSigningConfigException(sprintf('Expected an array at "%s".', $key));
        }
        $out = [];

        foreach ($value as $item) {
            if (! is_array($item)) {
                throw new InvalidSigningConfigException(sprintf('Expected objects at "%s".', $key));
            }

            /** @var array<string, mixed> $item */
            $out[] = $item;
        }

        return $out;
    }

    /** An RFC 3339 timestamp, or null when the key is absent. */
    /** @param array<string, mixed> $data */
    public static function timeOrNull(array $data, string $key): ?DateTimeImmutable
    {
        if (! isset($data[$key])) {
            return null;
        }

        try {
            return new DateTimeImmutable(self::string($data, $key));
        } catch (Exception $e) {
            throw new InvalidSigningConfigException(
                sprintf('Field "%s" is not a valid timestamp: %s', $key, $e->getMessage()),
                previous: $e,
            );
        }
    }
}
