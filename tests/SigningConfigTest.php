<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Tests;

use DateTimeImmutable;
use K2gl\SigstoreSign\Exception\InvalidSigningConfigException;
use K2gl\SigstoreSign\Internal\Json;
use K2gl\SigstoreSign\Service;
use K2gl\SigstoreSign\ServiceSelector;
use K2gl\SigstoreSign\SigningConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SigningConfig::class)]
#[CoversClass(Service::class)]
#[CoversClass(ServiceSelector::class)]
#[CoversClass(Json::class)]
#[CoversClass(InvalidSigningConfigException::class)]
final class SigningConfigTest extends TestCase
{
    public function testReadsThePublicGoodConfigAndItStillPointsAtRekorV1(): void
    {
        // arrange
        $config = SigningConfig::fromJson($this->fixture('signing-config-public-good.json'));

        // act
        $rekor = $config->rekorLog();

        // assert: this is the whole reason a client must read the config instead
        // of assuming — the default public instance is still Rekor v1
        fact($rekor->url)->is('https://rekor.sigstore.dev');
        fact($rekor->majorApiVersion)->is(1);
        fact($rekor->operator)->is('sigstore.dev');
        fact($config->certificateAuthority()->url)->is('https://fulcio.sigstore.dev');
        fact($config->oidcProvider()->url)->is('https://oauth2.sigstore.dev/auth');
        fact($config->timestampAuthorities()[0]->url)->is('https://timestamp.sigstore.dev/api/v1/timestamp');
    }

    public function testPrefersTheNewestSupportedVersionInTheRekorV2Config(): void
    {
        // arrange: the opt-in config lists a v2 log and keeps the v1 one
        $config = SigningConfig::fromJson($this->fixture('signing-config-rekor-v2.json'));

        // act + assert
        fact($config->rekorLog()->majorApiVersion)->is(2);

        // a client that only speaks v1 still gets the v1 log
        fact($config->rekorLog(supportedApiVersions: [1])->majorApiVersion)->is(1);
    }

    public function testSkipsAServiceThatWasNotLiveYet(): void
    {
        // arrange
        $config = SigningConfig::fromJson($this->fixture('signing-config-public-good.json'));

        // act + assert
        fact(static fn () => $config->rekorLog(at: new DateTimeImmutable('2019-01-01T00:00:00Z')))
            ->throws(InvalidSigningConfigException::class, 'Rekor log');
    }

    public function testRejectsAConfigWithTheWrongMediaType(): void
    {
        // act + assert
        fact(static fn () => SigningConfig::fromJson('{"mediaType":"application/json"}'))
            ->throws(InvalidSigningConfigException::class, 'mediaType');
    }

    public function testRejectsMalformedJson(): void
    {
        // act + assert
        fact(static fn () => SigningConfig::fromJson('not json'))
            ->throws(InvalidSigningConfigException::class);
    }

    public function testAllSelectorReturnsEveryLiveService(): void
    {
        // arrange
        $config = $this->configWith(
            logs: [
                $this->service('https://a.example', operator: 'a.example'),
                $this->service('https://b.example', operator: 'b.example'),
            ],
            selector: ServiceSelector::All,
        );

        // act + assert
        fact($config->rekorLogs())->count(2);
    }

    public function testExactSelectorTakesServicesFromDistinctOperators(): void
    {
        // arrange
        $config = $this->configWith(
            logs: [
                $this->service('https://a1.example', operator: 'a.example'),
                $this->service('https://a2.example', operator: 'a.example'),
                $this->service('https://b.example', operator: 'b.example'),
            ],
            selector: ServiceSelector::Exact,
            count: 2,
        );

        // act
        $logs = $config->rekorLogs();

        // assert
        fact(array_map(static fn (Service $s): string => $s->url, $logs))
            ->is(['https://a1.example', 'https://b.example']);
    }

    public function testExactSelectorFailsWhenOperatorsRunOut(): void
    {
        // arrange
        $config = $this->configWith(
            logs: [
                $this->service('https://a1.example', operator: 'a.example'),
                $this->service('https://a2.example', operator: 'a.example'),
            ],
            selector: ServiceSelector::Exact,
            count: 2,
        );

        // act + assert
        fact(static fn () => $config->rekorLogs())
            ->throws(InvalidSigningConfigException::class, 'distinct operators');
    }

    public function testAServiceIsValidOnBothEndpointsOfItsRange(): void
    {
        // arrange
        $service = new Service(
            url: 'https://log.example',
            majorApiVersion: 1,
            operator: 'log.example',
            validFrom: new DateTimeImmutable('2026-01-01T00:00:00Z'),
            validUntil: new DateTimeImmutable('2026-12-31T00:00:00Z'),
        );

        // act + assert
        fact($service->isValidAt(new DateTimeImmutable('2026-01-01T00:00:00Z')))->true();
        fact($service->isValidAt(new DateTimeImmutable('2026-12-31T00:00:00Z')))->true();
        fact($service->isValidAt(new DateTimeImmutable('2025-12-31T23:59:59Z')))->false();
        fact($service->isValidAt(new DateTimeImmutable('2027-01-01T00:00:00Z')))->false();
    }

    public function testRejectsAnExactSelectorWithoutACount(): void
    {
        // act + assert
        fact(fn () => SigningConfig::fromArray([
            'mediaType' => SigningConfig::MEDIA_TYPE,
            'rekorTlogConfig' => ['selector' => 'EXACT'],
        ]))->throws(InvalidSigningConfigException::class, 'count');
    }

    /** @param list<Service> $logs */
    private function configWith(array $logs, ServiceSelector $selector, int $count = 0): SigningConfig
    {
        return new SigningConfig(
            certificateAuthorities: [],
            oidcProviders: [],
            rekorLogs: $logs,
            timestampAuthorities: [],
            rekorSelector: $selector,
            rekorCount: $count,
        );
    }

    private function service(string $url, string $operator): Service
    {
        return new Service(url: $url, majorApiVersion: 2, operator: $operator);
    }

    private function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/' . $name);
        fact($contents)->isString();

        return $contents;
    }
}
