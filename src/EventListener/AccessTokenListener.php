<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use League\Bundle\OAuth2ServerBundle\Security\Authentication\Token\OAuth2Token;
use Mcp\Server\Authorization\AccessToken;
use Mcp\Server\Transport\Http\OAuth\ScopePolicy;
use Mcp\Server\Transport\StreamableHttpTransport;
use Omouren\McpOauthBundle\OAuth\JwtClaimReader;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Hands the League access token to MCP handlers. mcp/sdk 0.9 reads the request attribute
 * `AccessToken::class` and exposes it through `RequestContext::getAccessToken()`; mcp-bundle copies
 * Symfony request attributes to the PSR-7 request, so setting it here is enough.
 *
 * With `mcp_oauth.scope_policy`, it also answers 403 insufficient_scope (or 401 without a token)
 * when a method or tool needs a scope the token lacks, like the SDK AuthorizationMiddleware.
 *
 * Runs after the firewall (8) and ResourceAudienceListener (-8).
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#scope-challenge-handling
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: -16)]
final readonly class AccessTokenListener
{
    public function __construct(
        private TokenStorageInterface $tokenStorage,
        private JwtClaimReader $jwtClaimReader,
        private McpRequestGuard $mcpRequestGuard,
        private ?ScopePolicy $scopePolicy = null,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        // mcp/sdk before 0.9 (symfony/mcp-bundle before 0.15) has no AccessToken.
        if (!$event->isMainRequest() || !class_exists(AccessToken::class)) {
            return;
        }

        $request = $event->getRequest();
        // A CORS preflight never carries credentials.
        if (!$this->mcpRequestGuard->isResourcePath($request) || $request->isMethod('OPTIONS')) {
            return;
        }

        $token = $this->tokenStorage->getToken();
        $scopes = $token instanceof OAuth2Token ? $token->getScopes() : null;

        if (null !== $this->scopePolicy) {
            $payload = null;
            if ($request->isMethod('POST') && $this->scopePolicy->inspectsBody()) {
                $body = $this->boundedBody($request);
                if (null === $body) {
                    $event->setResponse($this->bodyTooLargeResponse());

                    return;
                }
                $payload = json_decode($body, true);
            }

            $required = $this->scopePolicy->requiredFor($payload);
            if (null === $scopes) {
                if ([] !== $required) {
                    $event->setResponse(new Response('', Response::HTTP_UNAUTHORIZED));
                }

                return;
            }

            // Handlers checking AccessToken::hasScope() see the hierarchy the policy enforces.
            $scopes = $this->scopePolicy->expand($scopes);
            if ([] !== array_diff($required, $scopes)) {
                $request->attributes->set(WwwAuthenticateListener::REQUIRED_SCOPES, $required);
                $event->setResponse(new Response('', Response::HTTP_FORBIDDEN));

                return;
            }
        }

        if (!$token instanceof OAuth2Token || null === $scopes) {
            return;
        }

        $request->attributes->set(AccessToken::class, new AccessToken($scopes, $this->claims($request, $token)));
    }

    /**
     * The JWT payload, already verified by the League resource server, plus `client_id` (RFC 9068):
     * League tokens carry the client only in `aud`, next to the RFC 8707 resource.
     *
     * @return array<string, mixed>
     */
    private function claims(Request $request, OAuth2Token $token): array
    {
        $header = $request->headers->get('Authorization', '');
        $claims = str_starts_with($header, 'Bearer ') ? $this->jwtClaimReader->payload(substr($header, 7)) ?? [] : [];

        $clientId = $token->getOAuthClientId();
        if ('' !== $clientId) {
            $claims += ['client_id' => $clientId];
        }

        return $claims;
    }

    /**
     * Reads at most the size the mcp-bundle transport accepts, so an oversized body is never held in memory.
     */
    private function boundedBody(Request $request): ?string
    {
        $stream = $request->getContent(true);
        $body = stream_get_contents($stream, StreamableHttpTransport::DEFAULT_MAX_BODY_BYTES + 1);

        return false === $body || \strlen($body) > StreamableHttpTransport::DEFAULT_MAX_BODY_BYTES ? null : $body;
    }

    private function bodyTooLargeResponse(): JsonResponse
    {
        return new JsonResponse([
            'jsonrpc' => '2.0',
            'id' => null,
            'error' => [
                'code' => -32600,
                'message' => \sprintf('Request body exceeds the maximum allowed size of %d bytes.', StreamableHttpTransport::DEFAULT_MAX_BODY_BYTES),
            ],
        ], Response::HTTP_REQUEST_ENTITY_TOO_LARGE);
    }
}
