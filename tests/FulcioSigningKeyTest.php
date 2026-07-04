<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Tests;

use K2gl\RekorClient\RekorClient;
use K2gl\SigstoreSign\Exception\FulcioException;
use K2gl\SigstoreSign\FulcioClient;
use K2gl\SigstoreSign\FulcioSigningKey;
use K2gl\SigstoreSign\Internal\Jwt;
use K2gl\SigstoreSign\Internal\Pem;
use K2gl\SigstoreSign\SigstoreSigner;
use K2gl\SigstoreSign\Tests\Support\MockTransport;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(FulcioSigningKey::class)]
#[CoversClass(FulcioClient::class)]
#[CoversClass(Jwt::class)]
#[CoversClass(Pem::class)]
final class FulcioSigningKeyTest extends TestCase
{
    private const SUB = 'https://github.com/k2gl/x/.github/workflows/ci.yml@refs/heads/main';

    public function testCreateProvesPossessionAndBindsTheFulcioCertificate(): void
    {
        $transport = $this->fulcioTransport();
        $key = FulcioSigningKey::create($this->fulcio($transport), $this->oidcToken());

        // The Fulcio request carries the ephemeral public key and a proof of
        // possession that really verifies over the token's sub, as DER ECDSA.
        $sent = json_decode($transport->requestBodyMatching('fulcio'), true);
        fact($sent['credentials']['oidcIdentityToken'])->is($this->oidcToken());
        fact($sent['publicKeyRequest']['publicKey']['algorithm'])->is('ECDSA');

        $publicKeyPem = $sent['publicKeyRequest']['publicKey']['content'];
        $proof = base64_decode($sent['publicKeyRequest']['proofOfPossession'], true);
        fact(openssl_verify(self::SUB, $proof, $publicKeyPem, OPENSSL_ALGO_SHA256))->is(1);

        // The resulting key drives the signer and emits a certificate bundle.
        $rekor = new RekorClient($transport, new Psr17Factory, new Psr17Factory, 'https://rekor.example');
        $bundle = (new SigstoreSigner($rekor))->signArtifact('artifact', $key)->toArray();
        fact(isset($bundle['verificationMaterial']['certificate']))->true();
    }

    public function testDetachedSctResponseIsAccepted(): void
    {
        $certPem = $this->certPem();
        $transport = new MockTransport([
            'fulcio' => fn (): ResponseInterface => $this->response(
                json_encode(['signedCertificateDetachedSct' => ['chain' => ['certificates' => [$certPem]]]]),
            ),
        ]);

        $key = FulcioSigningKey::create($this->fulcio($transport), $this->oidcToken());
        fact($key->rekorVerifier()->toArray()['x509Certificate']['rawBytes'])->is(base64_encode(Pem::toDer($certPem)));
    }

    public function testFulcioErrorStatusThrows(): void
    {
        $transport = new MockTransport([
            'fulcio' => fn (): ResponseInterface => $this->response('{"message":"invalid token"}', 400),
        ]);

        $this->expectException(FulcioException::class);
        FulcioSigningKey::create($this->fulcio($transport), $this->oidcToken());
    }

    public function testEmptyChainThrows(): void
    {
        $transport = new MockTransport([
            'fulcio' => fn (): ResponseInterface => $this->response('{"signedCertificateEmbeddedSct":{"chain":{"certificates":[]}}}'),
        ]);

        $this->expectException(FulcioException::class);
        FulcioSigningKey::create($this->fulcio($transport), $this->oidcToken());
    }

    public function testTokenWithoutSubThrows(): void
    {
        $noSub = 'h.' . rtrim(strtr(base64_encode((string) json_encode(['iss' => 'x'])), '+/', '-_'), '=') . '.s';

        $this->expectException(FulcioException::class);
        FulcioSigningKey::create($this->fulcio($this->fulcioTransport()), $noSub);
    }

    private function fulcioTransport(): MockTransport
    {
        return new MockTransport([
            'fulcio' => fn (): ResponseInterface => $this->response(
                json_encode(['signedCertificateEmbeddedSct' => ['chain' => ['certificates' => [$this->certPem()]]]]),
            ),
            'rekor' => fn (): ResponseInterface => $this->response((string) file_get_contents(__DIR__ . '/fixtures/rekor-entry.json')),
        ]);
    }

    private function fulcio(MockTransport $transport): FulcioClient
    {
        $factory = new Psr17Factory;

        return new FulcioClient($transport, $factory, $factory, 'https://fulcio.example');
    }

    private function oidcToken(): string
    {
        $payload = rtrim(strtr(base64_encode((string) json_encode(['sub' => self::SUB, 'iss' => 'x'])), '+/', '-_'), '=');

        return 'header.' . $payload . '.signature';
    }

    private function certPem(): string
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $csr = openssl_csr_new(['commonName' => 'test'], $key);
        $crt = openssl_csr_sign($csr, null, $key, 1);
        openssl_x509_export($crt, $pem);

        return $pem;
    }

    private function response(string $body, int $status = 200): ResponseInterface
    {
        $factory = new Psr17Factory;

        return $factory->createResponse($status)->withBody($factory->createStream($body));
    }
}
