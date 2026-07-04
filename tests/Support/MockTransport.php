<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Tests\Support;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * A PSR-18 client that records every request and replies from a per-URL-substring
 * handler map, so a test can drive the real RekorClient and TsaClient over a
 * mocked network and inspect exactly what was sent.
 */
final class MockTransport implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    private readonly Psr17Factory $factory;

    /** @param array<string, callable(RequestInterface): ResponseInterface> $handlers keyed by URL substring */
    public function __construct(private readonly array $handlers)
    {
        $this->factory = new Psr17Factory;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        foreach ($this->handlers as $needle => $handler) {
            if (str_contains((string) $request->getUri(), $needle)) {
                return $handler($request);
            }
        }

        return $this->factory->createResponse(404);
    }

    public function requestBodyMatching(string $needle): string
    {
        foreach ($this->requests as $request) {
            if (str_contains((string) $request->getUri(), $needle)) {
                return (string) $request->getBody();
            }
        }
        throw new RuntimeException("No request to a URL containing \"$needle\".");
    }
}
