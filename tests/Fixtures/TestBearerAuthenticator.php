<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Fixtures;

use League\Bundle\OAuth2ServerBundle\Security\Authentication\Token\OAuth2Token;
use Omouren\McpOauthBundle\OAuth\JwtClaimReader;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Stands in for the League OAuth2Authenticator without keys or persistence: it trusts the unsigned
 * JWT payload (`sub`, `scopes`, and `cid` for the client) and creates the same OAuth2Token League would.
 */
final class TestBearerAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    public function supports(Request $request): bool
    {
        return str_starts_with($request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $claims = (new JwtClaimReader())->payload(substr($request->headers->get('Authorization', ''), 7)) ?? [];
        $subject = \is_string($claims['sub'] ?? null) ? $claims['sub'] : '';

        $passport = new SelfValidatingPassport(new UserBadge($subject, static fn (string $identifier): InMemoryUser => new InMemoryUser($identifier, null)));
        $passport->setAttribute('clientId', \is_string($claims['cid'] ?? null) ? $claims['cid'] : '');
        $passport->setAttribute('scopes', \is_array($claims['scopes'] ?? null) ? array_values(array_filter($claims['scopes'], \is_string(...))) : []);

        return $passport;
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        /** @var string $clientId */
        $clientId = $passport->getAttribute('clientId');
        /** @var list<string> $scopes */
        $scopes = $passport->getAttribute('scopes');

        return new OAuth2Token($passport->getUser(), 'test-token', $clientId, $scopes, 'ROLE_OAUTH2_');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return new Response('', Response::HTTP_UNAUTHORIZED);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new Response('', Response::HTTP_UNAUTHORIZED);
    }
}
