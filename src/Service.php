<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign;

use DateTimeImmutable;
use K2gl\SigstoreSign\Exception\InvalidSigningConfigException;
use K2gl\SigstoreSign\Internal\Json;

/**
 * One service instance listed in a {@see SigningConfig}: where it is, which major
 * version of its API it speaks, who runs it, and when it was or is live.
 *
 * A service with only a start date is the most recent instance of that service —
 * but not necessarily the only valid one, so never assume a list has one entry.
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto
 */
final class Service
{
    public function __construct(
        public readonly string $url,
        public readonly int $majorApiVersion,
        public readonly string $operator,
        public readonly ?DateTimeImmutable $validFrom = null,
        public readonly ?DateTimeImmutable $validUntil = null,
    ) {
        if ($url === '') {
            throw new InvalidSigningConfigException('A signing-config service needs a URL.');
        }

        if ($majorApiVersion < 0) {
            throw new InvalidSigningConfigException('A signing-config service needs a major API version.');
        }
    }

    /** Whether the service was live at $moment. The validity range includes both endpoints. */
    public function isValidAt(DateTimeImmutable $moment): bool
    {
        if ($this->validFrom !== null && $moment < $this->validFrom) {
            return false;
        }

        return $this->validUntil === null || $moment <= $this->validUntil;
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $validFor = $data['validFor'] ?? [];

        if (! is_array($validFor)) {
            throw new InvalidSigningConfigException('"validFor" must be an object.');
        }

        /** @var array<string, mixed> $validFor */
        return new self(
            url: Json::string($data, 'url'),
            majorApiVersion: Json::int($data, 'majorApiVersion'),
            operator: Json::string($data, 'operator'),
            validFrom: Json::timeOrNull($validFor, 'start'),
            validUntil: Json::timeOrNull($validFor, 'end'),
        );
    }
}
