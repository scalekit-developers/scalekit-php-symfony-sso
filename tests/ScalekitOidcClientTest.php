<?php

namespace App\Tests;

use App\Service\ScalekitOidcClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

class ScalekitOidcClientTest extends TestCase
{
    private function client(): ScalekitOidcClient
    {
        $httpClient = new MockHttpClient(new MockResponse(json_encode([
            'authorization_endpoint' => 'https://your-env.scalekit.com/oauth/authorize',
            'token_endpoint' => 'https://your-env.scalekit.com/oauth/token',
            'jwks_uri' => 'https://your-env.scalekit.com/keys',
        ])));

        return new ScalekitOidcClient(
            $httpClient,
            'https://your-env.scalekit.com',
            'client-123',
            'secret-456',
            'http://localhost:8000/callback'
        );
    }

    public function testHandshakeModeOmitsRoutingParams(): void
    {
        $url = $this->client()->buildAuthorizationUrl('state-abc');

        $this->assertStringStartsWith('https://your-env.scalekit.com/oauth/authorize?', $url);
        $this->assertStringContainsString('client_id=client-123', $url);
        $this->assertStringContainsString('state=state-abc', $url);
        $this->assertStringContainsString('response_type=code', $url);
        $this->assertStringContainsString('redirect_uri=', $url);
        $this->assertStringNotContainsString('organization_id=', $url);
        $this->assertStringNotContainsString('connection_id=', $url);
        $this->assertStringNotContainsString('login_hint=', $url);
    }

    public function testModularModeSendsOrganizationId(): void
    {
        $url = $this->client()->buildAuthorizationUrl('state-abc', ['organization_id' => 'org_123']);

        $this->assertStringContainsString('organization_id=org_123', $url);
        $this->assertStringNotContainsString('connection_id=', $url);
        $this->assertStringNotContainsString('login_hint=', $url);
    }

    public function testModularModeSendsLoginHint(): void
    {
        $url = $this->client()->buildAuthorizationUrl('state-abc', ['login_hint' => 'jane@acme.com']);

        $this->assertStringContainsString('login_hint=jane%40acme.com', $url);
        $this->assertStringNotContainsString('organization_id=', $url);
    }

    public function testModularModeSendsConnectionId(): void
    {
        $url = $this->client()->buildAuthorizationUrl('state-abc', ['connection_id' => 'conn_123']);

        $this->assertStringContainsString('connection_id=conn_123', $url);
    }
}
