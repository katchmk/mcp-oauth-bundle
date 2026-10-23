<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Fixtures;

use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use Mcp\Server\Transport\Http\OAuth\ScopePolicy;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\AI\McpBundle\McpBundle;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Omouren\McpOauthBundle\McpOauthBundle;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        yield new TwigBundle();
        yield new McpBundle();
        yield new McpOauthBundle();
    }

    public function getProjectDir(): string
    {
        return \dirname(__DIR__, 2);
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'test',
            'test' => true,
            'http_method_override' => false,
            'php_errors' => ['log' => true],
            'router' => ['utf8' => true],
            'http_client' => ['default_options' => ['timeout' => 1]],
            'session' => ['storage_factory_id' => 'session.storage.factory.mock_file'],
            'csrf_protection' => true,
            'handle_all_throwables' => true,
        ]);
        $firewalls = [
            'main' => [
                'pattern' => '^/',
                'security' => false,
            ],
        ];
        $accessControl = [];
        if ('mcp' === $this->environment) {
            // Like the README: the MCP endpoint needs a League token with the "mcp" scope.
            $firewalls = ['mcp' => [
                'pattern' => '^/_mcp',
                'stateless' => true,
                'custom_authenticators' => [TestBearerAuthenticator::class],
            ]] + $firewalls;
            $accessControl[] = ['path' => '^/_mcp', 'roles' => 'ROLE_OAUTH2_MCP'];
        }
        $container->extension('security', [
            'providers' => ['memory' => ['memory' => null]],
            'firewalls' => $firewalls,
            'access_control' => $accessControl,
        ]);
        $container->extension('twig', [
            'default_path' => '%kernel.project_dir%/templates',
        ]);
        $container->extension('mcp', [
            'servers' => [
                'default' => [
                    'transports' => ['http' => true],
                    'http' => ['path' => '/_mcp'],
                    'registry' => '*',
                ],
            ],
        ]);
        $mcpOauthConfig = [
            'login_route' => 'app_login',
            'public_base_url' => 'https://mcp.example.test',
        ];
        if ('dcr_hardened' === $this->environment) {
            $container->extension('framework', [
                'cache' => [
                    'pools' => ['cache.test_rate_limiter' => ['adapter' => 'cache.adapter.filesystem']],
                ],
                'rate_limiter' => [
                    'mcp_oauth_register' => [
                        'policy' => 'fixed_window',
                        'limit' => 2,
                        'interval' => '1 hour',
                        'cache_pool' => 'cache.test_rate_limiter',
                    ],
                ],
            ]);
            $mcpOauthConfig['dcr'] = [
                'redirect_uri_schemes' => ['com.example.app'],
                'rate_limiter' => 'mcp_oauth_register',
            ];
        }
        // The scope policy needs mcp/sdk 0.9 (symfony/mcp-bundle 0.15+).
        if ('mcp' === $this->environment && class_exists(ScopePolicy::class)) {
            $mcpOauthConfig['scope_policy'] = [
                'tools' => ['delete-everything' => ['mcp:admin']],
                'implies' => ['mcp:root' => ['mcp:admin']],
            ];
        }
        $container->extension('mcp_oauth', $mcpOauthConfig);
        $container->services()
            ->set(AccessTokenTools::class)
                ->autoconfigure()
            ->set(TestBearerAuthenticator::class)
            ->set(UnauthorizedProbeController::class)
                ->public()
            ->set(DummyLoginController::class)
                ->public()
            ->set(InMemoryClientManager::class)
            ->alias(ClientManagerInterface::class, InMemoryClientManager::class);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import('@McpOauthBundle/config/routes.yaml');
        $routes->add('app_login', '/login')->controller(DummyLoginController::class);
        $routes->add('oauth2_authorize', '/oauth2/authorize')->controller(DummyLoginController::class);
        $routes->add('mcp_probe', '/_mcp')->controller(UnauthorizedProbeController::class)->methods(['GET']);
        // After the probe, so mcp-bundle only serves POST /_mcp.
        $routes->import('.', 'mcp');
    }
}
