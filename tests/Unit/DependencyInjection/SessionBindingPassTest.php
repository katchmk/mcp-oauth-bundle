<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\DependencyInjection;

use Mcp\Server\Session\FileSessionStore;
use Mcp\Server\Session\InMemorySessionStore;
use Omouren\McpOauthBundle\DependencyInjection\SessionBindingPass;
use Omouren\McpOauthBundle\Session\OwnerBoundSessionStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final class SessionBindingPassTest extends TestCase
{
    public function testDecoratesEveryServerSessionStore(): void
    {
        $container = $this->container(true);

        (new SessionBindingPass())->process($container);

        foreach (['default', 'admin.v2'] as $name) {
            $decorator = $container->getDefinition('mcp.server.'.$name.'.session.store.mcp_oauth_owner_bound');
            self::assertSame(OwnerBoundSessionStore::class, $decorator->getClass());
            self::assertSame(['mcp.server.'.$name.'.session.store', null, 0], $decorator->getDecoratedService());
        }
        self::assertFalse($container->hasDefinition('mcp.server.default.session.lock.mcp_oauth_owner_bound'));
    }

    public function testSkipsWhenDisabled(): void
    {
        $container = $this->container(false);

        (new SessionBindingPass())->process($container);

        self::assertFalse($container->hasDefinition('mcp.server.default.session.store.mcp_oauth_owner_bound'));
    }

    public function testSkipsWhenBundleIsNotLoaded(): void
    {
        $container = new ContainerBuilder();
        $container->register('mcp.server.default.session.store', InMemorySessionStore::class);

        (new SessionBindingPass())->process($container);

        self::assertFalse($container->hasDefinition('mcp.server.default.session.store.mcp_oauth_owner_bound'));
    }

    private function container(bool $sessionBinding): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('mcp_oauth.session_binding', $sessionBinding);
        $container->register('mcp.server.default.session.store', FileSessionStore::class);
        $container->register('mcp.server.admin.v2.session.store', InMemorySessionStore::class);
        $container->register('mcp.server.default.session.lock', \stdClass::class);

        return $container;
    }
}
