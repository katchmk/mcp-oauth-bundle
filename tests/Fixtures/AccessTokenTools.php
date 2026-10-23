<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Fixtures;

use Mcp\Capability\Attribute\McpTool;
use Mcp\Server\RequestContext;

/**
 * MCP tools that report the access token mcp-bundle hands to handlers.
 */
final class AccessTokenTools
{
    #[McpTool(name: 'whoami')]
    public function whoami(RequestContext $context): string
    {
        $token = $context->getAccessToken();

        return json_encode([
            'subject' => $token?->getSubject(),
            'client_id' => $token?->getClientId(),
            'scopes' => $token?->getScopes(),
        ], \JSON_THROW_ON_ERROR);
    }

    #[McpTool(name: 'delete-everything')]
    public function deleteEverything(): string
    {
        return 'deleted';
    }
}
