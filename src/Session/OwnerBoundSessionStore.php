<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Session;

use League\Bundle\OAuth2ServerBundle\Security\Authentication\Token\OAuth2Token;
use Mcp\Server\Session\SessionStoreInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Binds every mcp-bundle session to the user and OAuth client of the token that created it. For a request
 * with another token the session does not exist, so the SDK answers 404 as for an unknown id and a leaked
 * `Mcp-Session-Id` is useless without its owner's token.
 *
 * The session data is stored behind an owner fingerprint. Sessions stored without one, before the binding
 * was enabled, are unknown too: the client starts a new session.
 *
 * @see https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking
 */
final readonly class OwnerBoundSessionStore implements SessionStoreInterface
{
    private const PREFIX = 'mcp-oauth-owner:';

    public function __construct(
        private SessionStoreInterface $inner,
        private TokenStorageInterface $tokenStorage,
    ) {
    }

    public function exists(Uuid $id): bool
    {
        return $this->inner->exists($id) && false !== $this->read($id);
    }

    public function read(Uuid $id): string|false
    {
        $stored = $this->inner->read($id);
        if (false === $stored) {
            return false;
        }

        $header = $this->header();
        if (!hash_equals($header, substr($stored, 0, \strlen($header)))) {
            return false;
        }

        return substr($stored, \strlen($header));
    }

    public function write(Uuid $id, string $data): bool
    {
        // The SDK only writes sessions that exist() accepted; never overwrite one of another owner anyway.
        if ($this->ownedByAnother($id)) {
            return false;
        }

        return $this->inner->write($id, $this->header().$data);
    }

    public function destroy(Uuid $id): bool
    {
        if ($this->ownedByAnother($id)) {
            return false;
        }

        return $this->inner->destroy($id);
    }

    public function gc(): array
    {
        return $this->inner->gc();
    }

    private function ownedByAnother(Uuid $id): bool
    {
        return $this->inner->exists($id) && false === $this->read($id);
    }

    private function header(): string
    {
        $token = $this->tokenStorage->getToken();
        $clientId = $token instanceof OAuth2Token ? $token->getOAuthClientId() : null;

        return self::PREFIX.hash('sha256', serialize([$token?->getUserIdentifier(), $clientId]))."\n";
    }
}
