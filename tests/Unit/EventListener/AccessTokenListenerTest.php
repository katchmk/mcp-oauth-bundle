<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\EventListener;

use League\Bundle\OAuth2ServerBundle\Security\Authentication\Token\OAuth2Token;
use Mcp\Server\Authorization\AccessToken;
use Mcp\Server\Transport\Http\OAuth\ScopePolicy;
use Mcp\Server\Transport\StreamableHttpTransport;
use Omouren\McpOauthBundle\EventListener\AccessTokenListener;
use Omouren\McpOauthBundle\EventListener\WwwAuthenticateListener;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\JwtClaimReader;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use PHPUnit\Framework\Attributes\RequiresMethod;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;

#[RequiresMethod(ScopePolicy::class, 'requiredFor')]
final class AccessTokenListenerTest extends TestCase
{
    public function testSetsTheAccessTokenWithJwtClaimsAndClientId(): void
    {
        $request = $this->request('/_mcp', $this->jwt(['sub' => 'alice', 'jti' => 'abc']));

        $event = $this->dispatch($request, $this->oauthToken(['mcp']));

        self::assertNull($event->getResponse());
        $accessToken = $request->attributes->get(AccessToken::class);
        self::assertInstanceOf(AccessToken::class, $accessToken);
        self::assertSame(['mcp'], $accessToken->getScopes());
        self::assertSame('alice', $accessToken->getSubject());
        self::assertSame('client-a', $accessToken->getClientId());
        self::assertSame('abc', $accessToken->getClaim('jti'));
    }

    public function testKeepsAClientIdClaimOfTheJwt(): void
    {
        $request = $this->request('/_mcp', $this->jwt(['client_id' => 'from-jwt']));

        $this->dispatch($request, $this->oauthToken(['mcp']));

        $accessToken = $request->attributes->get(AccessToken::class);
        self::assertInstanceOf(AccessToken::class, $accessToken);
        self::assertSame('from-jwt', $accessToken->getClientId());
    }

    public function testIgnoresOtherPathsAndOtherTokens(): void
    {
        $request = $this->request('/api', $this->jwt([]));
        $this->dispatch($request, $this->oauthToken(['mcp']));
        self::assertFalse($request->attributes->has(AccessToken::class));

        $request = $this->request('/_mcp', $this->jwt([]));
        $this->dispatch($request, new NullToken());
        self::assertFalse($request->attributes->has(AccessToken::class));
    }

    public function testScopePolicyLetsPreflightThrough(): void
    {
        $request = $this->request('/_mcp', null, 'OPTIONS');

        $event = $this->dispatch($request, null, new ScopePolicy(default: ['mcp']));

        self::assertNull($event->getResponse());
    }

    public function testScopePolicyAsksForCredentialsWithoutToken(): void
    {
        $event = $this->dispatch($this->request('/_mcp', null), null, new ScopePolicy(default: ['mcp']));

        self::assertSame(401, $event->getResponse()?->getStatusCode());
    }

    public function testScopePolicyMarksMissingScopes(): void
    {
        $request = $this->request('/_mcp', $this->jwt([]), 'POST', $this->toolCall('delete-user'));

        $event = $this->dispatch($request, $this->oauthToken(['mcp']), new ScopePolicy(tools: ['delete-user' => ['mcp:admin', 'mcp:write']]));

        self::assertSame(403, $event->getResponse()?->getStatusCode());
        self::assertSame(['mcp:admin', 'mcp:write'], $request->attributes->get(WwwAuthenticateListener::REQUIRED_SCOPES));
        self::assertFalse($request->attributes->has(AccessToken::class));
    }

    public function testScopePolicyRejectsOversizedBody(): void
    {
        $body = str_repeat(' ', StreamableHttpTransport::DEFAULT_MAX_BODY_BYTES + 1);
        $request = $this->request('/_mcp', $this->jwt([]), 'POST', $body);

        $event = $this->dispatch($request, $this->oauthToken(['mcp']), new ScopePolicy(tools: ['delete-user' => ['mcp:admin']]));

        self::assertSame(413, $event->getResponse()?->getStatusCode());
    }

    /**
     * @param list<string> $scopes
     */
    private function oauthToken(array $scopes): OAuth2Token
    {
        return new OAuth2Token(new InMemoryUser('alice', null), 'token', 'client-a', $scopes, 'ROLE_OAUTH2_');
    }

    private function dispatch(Request $request, ?TokenInterface $token, ?ScopePolicy $scopePolicy = null): RequestEvent
    {
        $settings = new McpOauthSettings(
            resourcePaths: ['/_mcp'],
            authorizationPrefix: '/oauth2',
            scopes: ['mcp'],
            loginRoute: 'app_login',
            redirectQueryParam: '_target_path',
            consent: 'page',
            cimdEnabled: true,
            trustedDomains: [],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: true,
            publicBaseUrl: 'https://mcp.example.test',
        );
        $canonical = new CanonicalResourceUri();
        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken($token);

        $listener = new AccessTokenListener(
            $tokenStorage,
            new JwtClaimReader(),
            new McpRequestGuard($settings, new IssuerResolver($settings, $canonical), $canonical),
            $scopePolicy,
        );
        $event = new RequestEvent($this->createStub(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);
        $listener($event);

        return $event;
    }

    private function request(string $path, ?string $jwt, string $method = 'POST', string $content = ''): Request
    {
        $server = null === $jwt ? [] : ['HTTP_AUTHORIZATION' => 'Bearer '.$jwt];

        return Request::create('https://mcp.example.test'.$path, $method, server: $server, content: $content);
    }

    private function toolCall(string $name): string
    {
        return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/call', 'params' => ['name' => $name]], \JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function jwt(array $payload): string
    {
        $encode = static fn (array $data): string => rtrim(strtr(base64_encode(json_encode($data, \JSON_THROW_ON_ERROR)), '+/', '-_'), '=');

        return $encode(['alg' => 'none', 'typ' => 'JWT']).'.'.$encode($payload).'.x';
    }
}
