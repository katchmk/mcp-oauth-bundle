<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Functional;

use Mcp\Server\RequestContext;
use Mcp\Server\Transport\Http\OAuth\ScopePolicy;
use Omouren\McpOauthBundle\Tests\Fixtures\TestKernel;
use PHPUnit\Framework\Attributes\RequiresMethod;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Real MCP requests through the firewall, this bundle and the mcp-bundle server.
 */
final class McpEndpointTest extends WebTestCase
{
    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    #[RequiresMethod(RequestContext::class, 'getAccessToken')]
    public function testToolSeesTheAccessToken(): void
    {
        $client = self::createClient(['environment' => 'mcp']);
        $alice = $this->token('alice', 'client-a', ['mcp']);

        $result = $this->callTool($client, $alice, $this->initialize($client, $alice), 'whoami');

        self::assertSame(
            ['subject' => 'alice', 'client_id' => 'client-a', 'scopes' => ['mcp']],
            json_decode($this->toolText($result), true),
        );
    }

    public function testSessionIsBoundToItsOwner(): void
    {
        $client = self::createClient(['environment' => 'mcp']);
        $alice = $this->token('alice', 'client-a', ['mcp']);
        $sessionId = $this->initialize($client, $alice);

        $this->callTool($client, $this->token('bob', 'client-a', ['mcp']), $sessionId, 'whoami');
        self::assertResponseStatusCodeSame(404);

        $this->callTool($client, $this->token('alice', 'client-b', ['mcp']), $sessionId, 'whoami');
        self::assertResponseStatusCodeSame(404);

        $this->callTool($client, $alice, $sessionId, 'whoami');
        self::assertResponseStatusCodeSame(200);
    }

    #[RequiresMethod(ScopePolicy::class, 'requiredFor')]
    public function testScopePolicyAsksForTheMissingToolScope(): void
    {
        $client = self::createClient(['environment' => 'mcp']);
        $alice = $this->token('alice', 'client-a', ['mcp']);

        $this->callTool($client, $alice, $this->initialize($client, $alice), 'delete-everything');

        self::assertResponseStatusCodeSame(403);
        self::assertSame(
            'Bearer resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/_mcp", scope="mcp:admin", error="insufficient_scope"',
            $client->getResponse()->headers->get('WWW-Authenticate'),
        );
    }

    #[RequiresMethod(ScopePolicy::class, 'requiredFor')]
    public function testScopeHierarchyGrantsImpliedScopes(): void
    {
        $client = self::createClient(['environment' => 'mcp']);
        $root = $this->token('root', 'client-a', ['mcp', 'mcp:root']);
        $sessionId = $this->initialize($client, $root);

        self::assertSame('deleted', $this->toolText($this->callTool($client, $root, $sessionId, 'delete-everything')));

        $whoami = json_decode($this->toolText($this->callTool($client, $root, $sessionId, 'whoami')), true);
        self::assertIsArray($whoami);
        self::assertEqualsCanonicalizing(['mcp', 'mcp:root', 'mcp:admin'], $whoami['scopes']);
    }

    public function testFirewallDenialAsksForTheMcpScope(): void
    {
        $client = self::createClient(['environment' => 'mcp']);

        $this->post($client, $this->token('alice', 'client-a', ['profile']), null, $this->initializeMessage());

        self::assertResponseStatusCodeSame(403);
        self::assertSame(
            'Bearer resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/_mcp", scope="mcp", error="insufficient_scope"',
            $client->getResponse()->headers->get('WWW-Authenticate'),
        );
    }

    public function testRejectedHostGetsNoScopeChallenge(): void
    {
        $client = self::createClient(['environment' => 'mcp']);

        // mcp.http.allowed_hosts is not set, so mcp-bundle only accepts localhost.
        $this->post($client, $this->token('alice', 'client-a', ['mcp']), null, $this->initializeMessage(), 'mcp.example.test');

        self::assertResponseStatusCodeSame(403);
        self::assertFalse($client->getResponse()->headers->has('WWW-Authenticate'));
    }

    private function initialize(KernelBrowser $client, string $token): string
    {
        $this->post($client, $token, null, $this->initializeMessage());
        self::assertResponseStatusCodeSame(200);
        $sessionId = $client->getResponse()->headers->get('Mcp-Session-Id');
        self::assertIsString($sessionId);

        $this->post($client, $token, $sessionId, ['jsonrpc' => '2.0', 'method' => 'notifications/initialized']);
        self::assertResponseStatusCodeSame(202);

        return $sessionId;
    }

    /**
     * @return array<string, mixed>
     */
    private function callTool(KernelBrowser $client, string $token, string $sessionId, string $name): array
    {
        $this->post($client, $token, $sessionId, [
            'jsonrpc' => '2.0',
            'id' => 2,
            'method' => 'tools/call',
            'params' => ['name' => $name, 'arguments' => new \stdClass()],
        ]);

        $content = (string) $client->getInternalResponse()->getContent();
        // A JSON body, or one SSE "data:" line.
        if (1 === preg_match('/^data: (.+)$/m', $content, $matches)) {
            $content = $matches[1];
        }
        $message = json_decode($content, true);

        return \is_array($message) ? $message : [];
    }

    /**
     * @param array<string, mixed> $result
     */
    private function toolText(array $result): string
    {
        $text = $result['result']['content'][0]['text'] ?? null;
        self::assertIsString($text, (string) json_encode($result));

        return $text;
    }

    /**
     * @param array<string, mixed> $message
     */
    private function post(KernelBrowser $client, string $token, ?string $sessionId, array $message, string $host = 'localhost'): void
    {
        $server = [
            'HTTP_HOST' => $host,
            'HTTP_AUTHORIZATION' => 'Bearer '.$token,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json, text/event-stream',
            'HTTP_MCP_PROTOCOL_VERSION' => '2025-11-25',
        ];
        if (null !== $sessionId) {
            $server['HTTP_MCP_SESSION_ID'] = $sessionId;
        }

        $client->request('POST', '/_mcp', server: $server, content: json_encode($message, \JSON_THROW_ON_ERROR));
    }

    /**
     * @return array<string, mixed>
     */
    private function initializeMessage(): array
    {
        return [
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'initialize',
            'params' => [
                'protocolVersion' => '2025-11-25',
                'capabilities' => new \stdClass(),
                'clientInfo' => ['name' => 'test', 'version' => '1.0'],
            ],
        ];
    }

    /**
     * An unsigned token for TestBearerAuthenticator, bound to the MCP resource like League's.
     *
     * @param list<string> $scopes
     */
    private function token(string $subject, string $clientId, array $scopes): string
    {
        $encode = static fn (array $data): string => rtrim(strtr(base64_encode(json_encode($data, \JSON_THROW_ON_ERROR)), '+/', '-_'), '=');

        return $encode(['alg' => 'none', 'typ' => 'JWT']).'.'.$encode([
            'aud' => [$clientId, 'https://mcp.example.test/_mcp'],
            'sub' => $subject,
            'cid' => $clientId,
            'scopes' => $scopes,
        ]).'.x';
    }
}
