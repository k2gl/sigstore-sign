<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Tests;

use K2gl\Dsse\EcdsaP256Signer;
use K2gl\Dsse\Envelope;
use K2gl\Dsse\Pae;
use K2gl\Dsse\PublicKey;
use K2gl\RekorClient\KeyDetails;
use K2gl\RekorClient\RekorClient;
use K2gl\SigstoreSign\Internal\Der;
use K2gl\SigstoreSign\SigningKey;
use K2gl\SigstoreSign\SigstoreSigner;
use K2gl\SigstoreSign\TsaClient;
use K2gl\SigstoreSign\Tests\Support\MockTransport;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SigstoreSigner::class)]
#[CoversClass(SigningKey::class)]
#[CoversClass(TsaClient::class)]
#[CoversClass(Der::class)]
final class SigstoreSignerTest extends TestCase
{
    private string $privateKeyPem;
    private string $publicKeyPem;
    private string $publicKeyDer;

    protected function setUp(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        fact($key !== false)->true();
        openssl_pkey_export($key, $pem);
        $this->privateKeyPem = $pem;
        $details = openssl_pkey_get_details($key);
        fact($details !== false)->true();
        $this->publicKeyPem = $details['key'];
        $this->publicKeyDer = base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', $details['key']), true);
    }

    public function testSignArtifactProducesAVerifiableMessageSignatureBundle(): void
    {
        $transport = $this->transport();
        $signer = new SigstoreSigner($this->rekor($transport), $this->tsa($transport));

        $artifact = "hello sigstore-sign\n";
        $bundle = $signer->signArtifact($artifact, $this->key())->toArray();

        // The signature really verifies over the artifact.
        $signature = base64_decode($bundle['messageSignature']['signature'], true);
        fact(PublicKey::fromPem($this->publicKeyPem)->verify($artifact, $signature))->true();

        // Sigstore carries ECDSA signatures as ASN.1 DER, not raw r||s.
        fact(bin2hex($signature[0]))->is('30');

        // Shape: v0.3 message-signature bundle, digest = sha256(artifact), a tlog entry, a timestamp.
        fact($bundle['mediaType'])->is('application/vnd.dev.sigstore.bundle.v0.3+json');
        fact(base64_decode($bundle['messageSignature']['messageDigest']['digest'], true))->is(hash('sha256', $artifact, true));
        fact($bundle['verificationMaterial']['publicKey']['hint'])->is('the-hint');
        fact(count($bundle['verificationMaterial']['tlogEntries']))->is(1);
        fact(count($bundle['verificationMaterial']['timestampVerificationData']['rfc3161Timestamps']))->is(1);
    }

    public function testSignArtifactSubmitsTheArtifactDigestToRekor(): void
    {
        $transport = $this->transport();
        $signer = new SigstoreSigner($this->rekor($transport), $this->tsa($transport));

        $artifact = 'payload-bytes';
        $signer->signArtifact($artifact, $this->key());

        $sent = json_decode($transport->requestBodyMatching('rekor'), true);
        fact(base64_decode($sent['hashedRekordRequestV002']['digest'], true))->is(hash('sha256', $artifact, true));
    }

    public function testSignAttestationProducesADsseBundleSignedOverThePae(): void
    {
        $transport = $this->transport();
        $signer = new SigstoreSigner($this->rekor($transport), $this->tsa($transport));

        $payload = '{"_type":"https://in-toto.io/Statement/v1","subject":[]}';
        $type = 'application/vnd.in-toto+json';
        $bundle = $signer->signAttestation($payload, $type, $this->key())->toArray();

        // The envelope signature verifies over the PAE.
        $envelope = Envelope::fromArray($bundle['dsseEnvelope']);
        fact($envelope->verify(PublicKey::fromPem($this->publicKeyPem)))->is($payload);

        // Rekor bound the digest of the PAE, not the raw payload.
        $sent = json_decode($transport->requestBodyMatching('rekor'), true);
        fact(base64_decode($sent['hashedRekordRequestV002']['digest'], true))->is(hash('sha256', Pae::encode($type, $payload), true));
    }

    public function testWithoutATimestampAuthorityTheBundleHasNoTimestamps(): void
    {
        $transport = $this->transport();
        $signer = new SigstoreSigner($this->rekor($transport)); // no TSA

        $bundle = $signer->signArtifact('a', $this->key())->toArray();

        fact(isset($bundle['verificationMaterial']['timestampVerificationData']))->false();
    }

    public function testCertificateKeyEmitsACertificateBundle(): void
    {
        $transport = $this->transport();
        $signer = new SigstoreSigner($this->rekor($transport), $this->tsa($transport));

        $key = SigningKey::certificate(
            EcdsaP256Signer::fromPem($this->privateKeyPem, null),
            'fake-leaf-cert-der',
            KeyDetails::PKIX_ECDSA_P256_SHA_256,
        );
        $bundle = $signer->signArtifact('x', $key)->toArray();

        fact($bundle['verificationMaterial']['certificate']['rawBytes'])->is(base64_encode('fake-leaf-cert-der'));
    }

    private function key(): SigningKey
    {
        return SigningKey::publicKey(
            EcdsaP256Signer::fromPem($this->privateKeyPem, null),
            $this->publicKeyDer,
            KeyDetails::PKIX_ECDSA_P256_SHA_256,
            'the-hint',
        );
    }

    private function transport(): MockTransport
    {
        $factory = new Psr17Factory;
        $entry = (string) file_get_contents(__DIR__ . '/fixtures/rekor-entry.json');

        return new MockTransport([
            'rekor' => fn (RequestInterface $r): ResponseInterface => $factory->createResponse(200)->withBody($factory->createStream($entry)),
            'tsa' => fn (RequestInterface $r): ResponseInterface => $factory->createResponse(200)->withBody($factory->createStream($this->timestampResponse())),
        ]);
    }

    private function rekor(MockTransport $transport): RekorClient
    {
        $factory = new Psr17Factory;

        return new RekorClient($transport, $factory, $factory, 'https://rekor.example');
    }

    private function tsa(MockTransport $transport): TsaClient
    {
        $factory = new Psr17Factory;

        return new TsaClient($transport, $factory, $factory, 'https://tsa.example');
    }

    /** A minimal well-formed TimeStampResp: status granted, then a stand-in token. */
    private function timestampResponse(): string
    {
        return Der::sequence(
            Der::sequence(Der::integer(0)),
            Der::sequence(Der::integer(1234)),
        );
    }
}
