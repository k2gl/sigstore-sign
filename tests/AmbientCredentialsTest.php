<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Tests;

use K2gl\SigstoreSign\AmbientCredentials;
use K2gl\SigstoreSign\Exception\FulcioException;
use K2gl\SigstoreSign\Tests\Support\MockTransport;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(AmbientCredentials::class)]
final class AmbientCredentialsTest extends TestCase
{
    /** @var list<string> */
    private array $touchedEnv = [];

    protected function tearDown(): void
    {
        foreach ($this->touchedEnv as $name) {
            putenv($name);
        }
        $this->touchedEnv = [];
    }

    public function testGithubActionsExchangesTheRequestTokenForAnOidcToken(): void
    {
        $this->setEnv('ACTIONS_ID_TOKEN_REQUEST_URL', 'https://token.example/oidc');
        $this->setEnv('ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'runner-token');

        $captured = null;
        $transport = new MockTransport([
            'token.example' => function (RequestInterface $r) use (&$captured): ResponseInterface {
                $captured = $r;

                return $this->response('{"value":"the.oidc.jwt"}');
            },
        ]);
        $factory = new Psr17Factory;

        $token = AmbientCredentials::githubActions($transport, $factory);

        fact($token)->is('the.oidc.jwt');
        fact((string) $captured?->getUri())->is('https://token.example/oidc?audience=sigstore');
        fact($captured?->getHeaderLine('Authorization'))->is('Bearer runner-token');
    }

    public function testGithubActionsAppendsAudienceWhenUrlAlreadyHasQuery(): void
    {
        $this->setEnv('ACTIONS_ID_TOKEN_REQUEST_URL', 'https://token.example/oidc?foo=bar');
        $this->setEnv('ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'runner-token');

        $captured = null;
        $transport = new MockTransport([
            'token.example' => function (RequestInterface $r) use (&$captured): ResponseInterface {
                $captured = $r;

                return $this->response('{"value":"jwt"}');
            },
        ]);

        AmbientCredentials::githubActions($transport, new Psr17Factory, 'myaudience');
        fact((string) $captured?->getUri())->is('https://token.example/oidc?foo=bar&audience=myaudience');
    }

    public function testGithubActionsWithoutEnvThrows(): void
    {
        // arrange
        $this->setEnv('ACTIONS_ID_TOKEN_REQUEST_URL', '');
        $this->setEnv('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '');

        // act + assert
        fact(static fn () => AmbientCredentials::githubActions(new MockTransport([]), new Psr17Factory))
            ->throws(FulcioException::class);
    }

    public function testGithubActionsNon200Throws(): void
    {
        // arrange
        $this->setEnv('ACTIONS_ID_TOKEN_REQUEST_URL', 'https://token.example/oidc');
        $this->setEnv('ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'runner-token');
        $transport = new MockTransport(['token.example' => fn (): ResponseInterface => $this->response('nope', 403)]);

        // act + assert
        fact(static fn () => AmbientCredentials::githubActions($transport, new Psr17Factory))
            ->throws(FulcioException::class);
    }

    public function testGitlabReadsTheConfiguredVariable(): void
    {
        $this->setEnv('SIGSTORE_ID_TOKEN', 'gitlab.jwt.here');

        fact(AmbientCredentials::gitlabCi())->is('gitlab.jwt.here');
    }

    public function testGitlabMissingVariableThrows(): void
    {
        // arrange
        $this->setEnv('SIGSTORE_ID_TOKEN', '');

        // act + assert
        fact(static fn () => AmbientCredentials::gitlabCi())->throws(FulcioException::class);
    }

    private function setEnv(string $name, string $value): void
    {
        $this->touchedEnv[] = $name;
        putenv($value === '' ? $name : "$name=$value");
    }

    private function response(string $body, int $status = 200): ResponseInterface
    {
        $factory = new Psr17Factory;

        return $factory->createResponse($status)->withBody($factory->createStream($body));
    }
}
