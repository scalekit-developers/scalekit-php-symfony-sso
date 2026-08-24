<?php

namespace App\Service;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Minimal OIDC client for Scalekit Modular SSO.
 *
 * There is no official PHP SDK. This class talks standard OIDC:
 * discovery document, authorization-code redirect, back-channel token
 * exchange, JWKS-verified id_token.
 *
 * Scalekit routing params are optional here so the same client can run
 * Mode A (handshake only) and Mode B (modular routing).
 */
class ScalekitOidcClient
{
    private ?array $discovery = null;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly string $environmentUrl,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly string $redirectUri,
    ) {
    }

    /**
     * Build the authorization URL.
     *
     * $ssoParams may include connection_id, organization_id, and/or login_hint.
     * Scalekit evaluates them in that precedence order. Omit all three for
     * Mode A. Pass exactly one for Mode B.
     */
    public function buildAuthorizationUrl(string $state, array $ssoParams = []): string
    {
        $params = array_filter([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'state' => $state,
            'connection_id' => $ssoParams['connection_id'] ?? null,
            'organization_id' => $ssoParams['organization_id'] ?? null,
            'login_hint' => $ssoParams['login_hint'] ?? null,
        ], static fn ($value) => $value !== null && $value !== '');

        return $this->discovery()['authorization_endpoint'].'?'.http_build_query($params);
    }

    /**
     * Exchange an authorization code for verified id_token claims.
     */
    public function exchangeCodeForClaims(string $code): array
    {
        $response = $this->httpClient->request('POST', $this->discovery()['token_endpoint'], [
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->redirectUri,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
            ],
        ]);

        $idToken = $response->toArray()['id_token'] ?? null;
        if ($idToken === null) {
            throw new \RuntimeException('Token response did not include an id_token.');
        }

        return $this->verifyIdToken($idToken);
    }

    private function verifyIdToken(string $idToken): array
    {
        $jwks = $this->httpClient->request('GET', $this->discovery()['jwks_uri'])->toArray();
        $keys = JWK::parseKeySet($jwks);

        return (array) JWT::decode($idToken, $keys);
    }

    private function discovery(): array
    {
        if ($this->discovery === null) {
            $this->discovery = $this->httpClient
                ->request('GET', rtrim($this->environmentUrl, '/').'/.well-known/openid-configuration')
                ->toArray();
        }

        return $this->discovery;
    }
}
