<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Omouren\McpOauthBundle\OAuth\WwwAuthenticateHeader;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * A 403 gets `insufficient_scope` only when it comes with REQUIRED_SCOPES: Symfony Security denied access,
 * or the scope policy found a missing scope. mcp-bundle also answers 403 for a Host or Origin header its
 * DNS rebinding protection rejects, and a scope challenge there would send clients into a re-authorization loop.
 */
#[AsEventListener(event: KernelEvents::EXCEPTION, method: 'onKernelException', priority: 2)]
#[AsEventListener(event: KernelEvents::RESPONSE, priority: 0)]
final readonly class WwwAuthenticateListener
{
    /**
     * Request attribute with the scopes a 403 response asks for.
     */
    public const REQUIRED_SCOPES = '_mcp_oauth_required_scopes';

    public function __construct(
        private McpOauthSettings $settings,
        private IssuerResolver $issuerResolver,
        private WwwAuthenticateHeader $wwwAuthenticateHeader,
        private McpRequestGuard $mcpRequestGuard,
    ) {
    }

    /**
     * Runs before the Security ExceptionListener (1) turns the AccessDeniedException into a 403.
     */
    public function onKernelException(ExceptionEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        if (!$this->mcpRequestGuard->isResourcePath($request) || $request->attributes->has(self::REQUIRED_SCOPES)) {
            return;
        }

        for ($throwable = $event->getThrowable(); null !== $throwable; $throwable = $throwable->getPrevious()) {
            if ($throwable instanceof AccessDeniedException || $throwable instanceof AccessDeniedHttpException) {
                $request->attributes->set(self::REQUIRED_SCOPES, $this->settings->scopes);

                return;
            }
        }
    }

    public function __invoke(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        if (!$this->mcpRequestGuard->isResourcePath($request)) {
            return;
        }

        $response = $event->getResponse();
        $status = $response->getStatusCode();
        if (Response::HTTP_UNAUTHORIZED !== $status && Response::HTTP_FORBIDDEN !== $status) {
            return;
        }

        $error = null;
        $scopes = $this->settings->scopes;
        if (Response::HTTP_FORBIDDEN === $status) {
            $required = $request->attributes->get(self::REQUIRED_SCOPES);
            if (!\is_array($required)) {
                return;
            }
            $error = 'insufficient_scope';
            $scopes = array_values(array_filter($required, \is_string(...)));
        } elseif (str_starts_with($request->headers->get('Authorization', ''), 'Bearer ')) {
            $error = 'invalid_token';
        }
        $header = $this->wwwAuthenticateHeader->format(
            $this->issuerResolver->protectedResourceMetadataUrl($request),
            $scopes,
            $error,
        );
        $response->headers->set('WWW-Authenticate', $header);
        $response->headers->set('Access-Control-Expose-Headers', 'WWW-Authenticate');
        $response->headers->remove('Mcp-Session-Id');
    }
}
