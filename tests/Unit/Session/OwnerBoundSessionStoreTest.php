<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\Session;

use League\Bundle\OAuth2ServerBundle\Security\Authentication\Token\OAuth2Token;
use Mcp\Server\Session\InMemorySessionStore;
use Omouren\McpOauthBundle\Session\OwnerBoundSessionStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Uid\Uuid;

final class OwnerBoundSessionStoreTest extends TestCase
{
    private InMemorySessionStore $inner;
    private TokenStorage $tokenStorage;
    private OwnerBoundSessionStore $store;

    protected function setUp(): void
    {
        $this->inner = new InMemorySessionStore();
        $this->tokenStorage = new TokenStorage();
        $this->store = new OwnerBoundSessionStore($this->inner, $this->tokenStorage);
    }

    public function testOwnerReadsItsSession(): void
    {
        $id = Uuid::v4();
        $this->authenticate('alice', 'client-a');

        self::assertTrue($this->store->write($id, '{"a":1}'));

        self::assertTrue($this->store->exists($id));
        self::assertSame('{"a":1}', $this->store->read($id));
    }

    public function testAnotherUserOrClientDoesNotSeeTheSession(): void
    {
        $id = Uuid::v4();
        $this->authenticate('alice', 'client-a');
        $this->store->write($id, '{"a":1}');

        foreach ([['bob', 'client-a'], ['alice', 'client-b']] as [$user, $client]) {
            $this->authenticate($user, $client);
            self::assertFalse($this->store->exists($id));
            self::assertFalse($this->store->read($id));
        }

        $this->tokenStorage->setToken(null);
        self::assertFalse($this->store->exists($id));
    }

    public function testAnotherOwnerCannotOverwriteOrDestroyTheSession(): void
    {
        $id = Uuid::v4();
        $this->authenticate('alice', 'client-a');
        $this->store->write($id, '{"a":1}');

        $this->authenticate('bob', 'client-a');
        self::assertFalse($this->store->write($id, '{"b":1}'));
        self::assertFalse($this->store->destroy($id));

        $this->authenticate('alice', 'client-a');
        self::assertSame('{"a":1}', $this->store->read($id));
        self::assertTrue($this->store->destroy($id));
        self::assertFalse($this->inner->exists($id));
    }

    public function testSessionWithoutOwnerIsUnknown(): void
    {
        $id = Uuid::v4();
        $this->inner->write($id, '{"a":1}');
        $this->authenticate('alice', 'client-a');

        self::assertFalse($this->store->exists($id));
        self::assertFalse($this->store->read($id));
    }

    public function testAnonymousSessionsStayAnonymous(): void
    {
        $id = Uuid::v4();

        self::assertTrue($this->store->write($id, '{"a":1}'));
        self::assertSame('{"a":1}', $this->store->read($id));

        $this->authenticate('alice', 'client-a');
        self::assertFalse($this->store->exists($id));
    }

    private function authenticate(string $user, string $clientId): void
    {
        $this->tokenStorage->setToken(new OAuth2Token(new InMemoryUser($user, null), 'token', $clientId, ['mcp'], 'ROLE_OAUTH2_'));
    }
}
