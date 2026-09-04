<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign;

use DateTimeImmutable;
use JsonException;
use K2gl\SigstoreSign\Exception\InvalidSigningConfigException;
use K2gl\SigstoreSign\Internal\Json;

/**
 * Sigstore's signing config: which Fulcio, OIDC issuer, Rekor logs and timestamp
 * authorities to sign against, and how many of each to use. Sigstore ships it as
 * a TUF target, so it is the answer to "where do I sign?" that a client should
 * ask instead of hard-coding URLs — the more so now that Rekor v2 log URLs rotate
 * and that the default config still points at Rekor **v1**.
 *
 * Fetch it through {@see \K2gl\Tuf\Updater} alongside the trusted root:
 *
 * ```php
 * $target = $updater->getTargetInfo('signing_config.v0.2.json');
 * $config = SigningConfig::fromJson($updater->downloadTarget($target));
 *
 * $log = $config->rekorLog();
 * $rekor = new RekorClient(
 *     $http, $psr17, $psr17,
 *     baseUrl: $log->url,
 *     apiVersion: RekorApiVersion::from($log->majorApiVersion),
 * );
 * ```
 *
 * Selection follows the spec: a service is a candidate when it was live at the
 * chosen moment and speaks an API version the caller supports; of those, the
 * newest supported version wins (a client must not mix versions), and the
 * service config's selector decides how many come back — with `EXACT` taking
 * them from distinct operators.
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto
 */
final class SigningConfig
{
    public const MEDIA_TYPE = 'application/vnd.dev.sigstore.signingconfig.v0.2+json';

    /**
     * @param list<Service> $certificateAuthorities
     * @param list<Service> $oidcProviders
     * @param list<Service> $rekorLogs
     * @param list<Service> $timestampAuthorities
     */
    public function __construct(
        private readonly array $certificateAuthorities,
        private readonly array $oidcProviders,
        private readonly array $rekorLogs,
        private readonly array $timestampAuthorities,
        private readonly ServiceSelector $rekorSelector = ServiceSelector::Any,
        private readonly int $rekorCount = 0,
        private readonly ServiceSelector $timestampSelector = ServiceSelector::Any,
        private readonly int $timestampCount = 0,
    ) {}

    /**
     * The Fulcio instance to request a signing certificate from.
     *
     * @param list<int> $supportedApiVersions
     */
    public function certificateAuthority(?DateTimeImmutable $at = null, array $supportedApiVersions = [1]): Service
    {
        return $this->one($this->certificateAuthorities, 'certificate authority', $at, $supportedApiVersions);
    }

    /**
     * The OIDC issuer to get an identity token from.
     *
     * @param list<int> $supportedApiVersions
     */
    public function oidcProvider(?DateTimeImmutable $at = null, array $supportedApiVersions = [1]): Service
    {
        return $this->one($this->oidcProviders, 'OIDC provider', $at, $supportedApiVersions);
    }

    /**
     * One Rekor log to submit to — the common case, and what the public config
     * asks for. Use {@see self::rekorLogs()} when the config selects several.
     *
     * @param list<int> $supportedApiVersions
     */
    public function rekorLog(?DateTimeImmutable $at = null, array $supportedApiVersions = [1, 2]): Service
    {
        return $this->one($this->rekorLogs, 'Rekor log', $at, $supportedApiVersions);
    }

    /**
     * Every Rekor log the config's selector asks a client to write to.
     *
     * @param  list<int>     $supportedApiVersions
     * @return list<Service>
     */
    public function rekorLogs(?DateTimeImmutable $at = null, array $supportedApiVersions = [1, 2]): array
    {
        return $this->select(
            services: $this->rekorLogs,
            kind: 'Rekor log',
            selector: $this->rekorSelector,
            count: $this->rekorCount,
            at: $at,
            supportedApiVersions: $supportedApiVersions,
        );
    }

    /**
     * Every timestamp authority the config's selector asks a client to use. Empty
     * when the config lists none — a Rekor v1 entry carries its own integrated
     * time, so a timestamp is not always needed.
     *
     * @param  list<int>     $supportedApiVersions
     * @return list<Service>
     */
    public function timestampAuthorities(?DateTimeImmutable $at = null, array $supportedApiVersions = [1]): array
    {
        if ($this->timestampAuthorities === []) {
            return [];
        }

        return $this->select(
            services: $this->timestampAuthorities,
            kind: 'timestamp authority',
            selector: $this->timestampSelector,
            count: $this->timestampCount,
            at: $at,
            supportedApiVersions: $supportedApiVersions,
        );
    }

    public static function fromJson(string $json): self
    {
        try {
            /** @var mixed $data */
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidSigningConfigException('Signing config is not valid JSON: ' . $e->getMessage(), previous: $e);
        }

        if (! is_array($data)) {
            throw new InvalidSigningConfigException('Signing config must be a JSON object.');
        }

        /** @var array<string, mixed> $data */
        return self::fromArray($data);
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $mediaType = $data['mediaType'] ?? null;

        if ($mediaType !== self::MEDIA_TYPE) {
            throw new InvalidSigningConfigException(sprintf(
                'Signing config mediaType is %s, expected "%s".',
                is_string($mediaType) ? '"' . $mediaType . '"' : 'missing',
                self::MEDIA_TYPE,
            ));
        }
        [$rekorSelector, $rekorCount] = self::serviceConfig($data, 'rekorTlogConfig');
        [$tsaSelector, $tsaCount] = self::serviceConfig($data, 'tsaConfig');

        return new self(
            certificateAuthorities: self::services($data, 'caUrls'),
            oidcProviders: self::services($data, 'oidcUrls'),
            rekorLogs: self::services($data, 'rekorTlogUrls'),
            timestampAuthorities: self::services($data, 'tsaUrls'),
            rekorSelector: $rekorSelector,
            rekorCount: $rekorCount,
            timestampSelector: $tsaSelector,
            timestampCount: $tsaCount,
        );
    }

    /**
     * @param  array<string, mixed> $data
     * @return list<Service>
     */
    private static function services(array $data, string $key): array
    {
        $services = [];

        foreach (Json::objectList($data, $key) as $raw) {
            $services[] = Service::fromArray($raw);
        }

        return $services;
    }

    /**
     * @param  array<string, mixed> $data
     * @return array{0: ServiceSelector, 1: int}
     */
    private static function serviceConfig(array $data, string $key): array
    {
        $config = $data[$key] ?? null;

        if ($config === null) {
            return [ServiceSelector::Any, 0];
        }

        if (! is_array($config)) {
            throw new InvalidSigningConfigException(sprintf('"%s" must be an object.', $key));
        }

        /** @var array<string, mixed> $config */
        $selector = ServiceSelector::tryFrom(Json::string($config, 'selector'));

        if ($selector === null) {
            throw new InvalidSigningConfigException(sprintf('"%s" has an unknown selector.', $key));
        }
        $count = isset($config['count']) ? Json::int($config, 'count') : 0;

        if ($selector === ServiceSelector::Exact && $count < 1) {
            throw new InvalidSigningConfigException(sprintf('"%s" selects EXACT services but gives no count.', $key));
        }

        return [$selector, $count];
    }

    /**
     * @param list<Service> $services
     * @param list<int>     $supportedApiVersions
     */
    private function one(array $services, string $kind, ?DateTimeImmutable $at, array $supportedApiVersions): Service
    {
        return $this->select(
            services: $services,
            kind: $kind,
            selector: ServiceSelector::Any,
            count: 0,
            at: $at,
            supportedApiVersions: $supportedApiVersions,
        )[0];
    }

    /**
     * @param  list<Service> $services
     * @param  list<int>     $supportedApiVersions
     * @return non-empty-list<Service>
     */
    private function select(
        array $services,
        string $kind,
        ServiceSelector $selector,
        int $count,
        ?DateTimeImmutable $at,
        array $supportedApiVersions,
    ): array {
        $moment = $at ?? new DateTimeImmutable;
        $byVersion = [];

        foreach ($services as $service) {
            if ($service->isValidAt($moment) && in_array($service->majorApiVersion, $supportedApiVersions, true)) {
                $byVersion[$service->majorApiVersion][] = $service;
            }
        }

        if ($byVersion === []) {
            throw new InvalidSigningConfigException(sprintf(
                'The signing config has no %s that was live at %s and speaks API version %s.',
                $kind,
                $moment->format(DATE_RFC3339),
                implode(' or ', array_map(strval(...), $supportedApiVersions)),
            ));
        }
        // A client must not mix API versions, so keep only the newest one on offer.
        $candidates = $byVersion[max(array_keys($byVersion))];

        return match ($selector) {
            ServiceSelector::All => $candidates,
            ServiceSelector::Any => [$candidates[0]],
            ServiceSelector::Exact => self::distinctOperators($candidates, $count, $kind),
        };
    }

    /**
     * @param  non-empty-list<Service> $candidates
     * @return non-empty-list<Service>
     */
    private static function distinctOperators(array $candidates, int $count, string $kind): array
    {
        $picked = [];
        $operators = [];

        foreach ($candidates as $service) {
            if (in_array($service->operator, $operators, true)) {
                continue;
            }
            $operators[] = $service->operator;
            $picked[] = $service;

            if (count($picked) === $count) {
                return $picked;
            }
        }

        throw new InvalidSigningConfigException(sprintf(
            'The signing config asks for %d %s services from distinct operators but offers only %d.',
            $count,
            $kind,
            count($picked),
        ));
    }
}
