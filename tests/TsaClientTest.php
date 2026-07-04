<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Tests;

use K2gl\SigstoreSign\Exception\TimestampException;
use K2gl\SigstoreSign\Internal\Der;
use K2gl\SigstoreSign\TsaClient;
use K2gl\SigstoreSign\Tests\Support\MockTransport;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(TsaClient::class)]
#[CoversClass(Der::class)]
#[CoversClass(TimestampException::class)]
final class TsaClientTest extends TestCase
{
    public function testBuildsAnRfc3161RequestOverTheSignatureDigest(): void
    {
        $transport = $this->transport(fn (): ResponseInterface => $this->ok($this->grantedResponse('the-token')));
        $this->client($transport)->timestamp('my-signature');

        $request = Der::read($transport->requestBodyMatching('tsa'), 0);
        fact($request['tag'])->is(0x30); // TimeStampReq SEQUENCE

        // version INTEGER 1
        $version = Der::read($transport->requestBodyMatching('tsa'), $request['contentStart']);
        fact($version['tag'])->is(0x02);

        // messageImprint carries sha256(signature)
        $body = $transport->requestBodyMatching('tsa');
        fact(str_contains($body, hash('sha256', 'my-signature', true)))->true();
    }

    public function testReturnsTheTokenFromAGrantedResponse(): void
    {
        $token = Der::sequence(Der::integer(99));
        $transport = $this->transport(fn (): ResponseInterface => $this->ok($this->grantedResponse($token)));

        fact($this->client($transport)->timestamp('sig'))->is($token);
    }

    public function testRejectionStatusThrows(): void
    {
        // PKIStatus 2 = rejection
        $response = Der::sequence(Der::sequence(Der::integer(2)));
        $transport = $this->transport(fn (): ResponseInterface => $this->ok($response));

        $this->expectException(TimestampException::class);
        $this->client($transport)->timestamp('sig');
    }

    public function testMissingTokenThrows(): void
    {
        $response = Der::sequence(Der::sequence(Der::integer(0))); // granted but no token
        $transport = $this->transport(fn (): ResponseInterface => $this->ok($response));

        $this->expectException(TimestampException::class);
        $this->client($transport)->timestamp('sig');
    }

    public function testNon200Throws(): void
    {
        $transport = $this->transport(fn (): ResponseInterface => (new Psr17Factory)->createResponse(500));

        $this->expectException(TimestampException::class);
        $this->client($transport)->timestamp('sig');
    }

    public function testEmptyBodyThrows(): void
    {
        $transport = $this->transport(fn (): ResponseInterface => $this->ok(''));

        $this->expectException(TimestampException::class);
        $this->client($transport)->timestamp('sig');
    }

    public function testTransportErrorThrows(): void
    {
        $transport = $this->transport(function (): ResponseInterface {
            throw new class ('down') extends RuntimeException implements ClientExceptionInterface {};
        });

        $this->expectException(TimestampException::class);
        $this->client($transport)->timestamp('sig');
    }

    private function grantedResponse(string $token): string
    {
        return Der::sequence(Der::sequence(Der::integer(0)), $token);
    }

    private function ok(string $body): ResponseInterface
    {
        $factory = new Psr17Factory;

        return $factory->createResponse(200)->withBody($factory->createStream($body));
    }

    /** @param callable(RequestInterface): ResponseInterface $handler */
    private function transport(callable $handler): MockTransport
    {
        return new MockTransport(['tsa' => $handler]);
    }

    private function client(MockTransport $transport): TsaClient
    {
        $factory = new Psr17Factory;

        return new TsaClient($transport, $factory, $factory, 'https://tsa.example/timestamp');
    }
}
