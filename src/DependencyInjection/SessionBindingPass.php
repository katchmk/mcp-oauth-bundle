<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\DependencyInjection;

use Omouren\McpOauthBundle\Session\OwnerBoundSessionStore;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Decorates the session store of every mcp-bundle server (`mcp.server.<name>.session.store`)
 * with OwnerBoundSessionStore, unless `mcp_oauth.session_binding` is false.
 */
final class SessionBindingPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasParameter('mcp_oauth.session_binding') || true !== $container->getParameter('mcp_oauth.session_binding')) {
            return;
        }

        foreach (array_keys($container->getDefinitions()) as $id) {
            if (1 !== preg_match('/^mcp\.server\..+\.session\.store$/', $id)) {
                continue;
            }

            $container->register($id.'.mcp_oauth_owner_bound', OwnerBoundSessionStore::class)
                ->setDecoratedService($id)
                ->setArguments([new Reference('.inner'), new Reference('security.token_storage')]);
        }
    }
}
