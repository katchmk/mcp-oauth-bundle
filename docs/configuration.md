# Configuration reference

Install, League wiring, and `security.yaml` live in the [Getting started](../README.md#getting-started) section of the README. This page is the `mcp_oauth` option list.

## Options

| Key | Type | Default | Required |
|---|---|---|---|
| `authorization_prefix` | string | `/oauth2` | no |
| `scopes` | string[] | `[mcp]` | no |
| `login_route` | string | | yes |
| `redirect_query_param` | string | `_target_path` | no |
| `consent` | `page` or `auto` | `page` | no |
| `cimd.enabled` | bool | `true` | no |
| `cimd.trusted_domains` | string[] | claude.ai, vscode.dev, cursor.com | no |
| `dcr.enabled` | bool | `true` | no |
| `dcr.redirect_uri_schemes` | string[] | `[]` | no |
| `dcr.rate_limiter` | string or null | `null` | no |
| `scope_policy.default` | string[] | `[]` | no |
| `scope_policy.methods` | map of string[] | `{}` | no |
| `scope_policy.tools` | map of string[] | `{}` | no |
| `scope_policy.implies` | map of string[] | `{}` | no |
| `session_binding` | bool | `true` | no |
| `resource_indicators` | bool | `true` | no |
| `issuer_identification` | bool | `true` | no |
| `public_base_url` | string or null | `null` | yes, unless `framework.trusted_hosts` is set |

```yaml
mcp_oauth:
    # Used in metadata URLs and this bundle's register/consent paths.
    # Import League authorize/token with the same prefix.
    authorization_prefix: /oauth2

    # Advertised scopes_supported, and the scopes that mark authorize/token as MCP when RFC 8707 resource is absent.
    scopes: [mcp]

    # Required. Symfony route name of your login page, not a URL.
    login_route: app_login

    # Query parameter on the login URL that receives the MCP authorize request URI.
    # Keep _target_path for Symfony form_login; change it if your login reads another name.
    redirect_query_param: _target_path

    # page = Twig consent; auto = approve after login.
    consent: page

    cimd:
        enabled: true
        trusted_domains:
            - claude.ai
            - vscode.dev
            - cursor.com

    dcr:
        enabled: true   # Deprecated; see docs/deprecations.md
        # Extra redirect URI schemes for native apps (RFC 8252), e.g. com.example.app.
        # https and loopback http (127.0.0.1, [::1], localhost) are always accepted.
        redirect_uri_schemes: []
        # Name of a framework.rate_limiter limiter, applied per client IP.
        rate_limiter: ~

    # Scopes MCP requests need besides the firewall checks (mcp-bundle 0.15+). See "Scope policy".
    scope_policy:
        default: []
        methods: {}
        tools: {}
        implies: {}

    # Bind each mcp-bundle session to the user and client that created it. See "Session binding".
    session_binding: true

    resource_indicators: true
    issuer_identification: true

    # Public origin used as issuer and MCP resource base.
    public_base_url: https://mcp.example.com
```

`authorization_prefix` must match the prefix you use to import League routes. `scopes` must stay in sync with League `scopes.available`.

Set `public_base_url` to the public origin of the app. Without it, the issuer and the MCP resource URIs are built from the request `Host` header and the metadata is cached publicly, so anyone could poison a shared cache with a forged host. Leaving it empty is only allowed when [`framework.trusted_hosts`](https://symfony.com/doc/current/reference/configuration/framework.html#trusted-hosts) is configured; otherwise the container fails to compile. Behind a reverse proxy, also configure Symfony `trusted_proxies`.

HTTP paths come from mcp-bundle `mcp.servers.*.http.path` (not from this bundle). Every HTTP server is a protected resource. The firewall `pattern` is written in the app (`^/_mcp`, or a regex covering several paths).

Also set mcp-bundle `mcp.servers.*.http.allowed_hosts` to the host of `public_base_url`, and `allowed_origins` for browser clients (mcp-bundle 0.15+). Otherwise the DNS rebinding protection of mcp-bundle answers 403 for every request that does not come from `localhost`. This bundle adds `insufficient_scope` only to a 403 from Symfony Security or from the scope policy, never to these.

## Scope policy

The firewall decides whether a token may call the MCP endpoint at all (for example `ROLE_OAUTH2_MCP`). `scope_policy` adds the scopes a JSON-RPC method or a tool needs, with the same rules as the mcp/sdk `ScopePolicy`. It requires mcp-bundle 0.15+; with an older version the container fails to compile.

```yaml
mcp_oauth:
    scope_policy:
        default: [mcp]                       # every MCP request
        methods:
            'resources/read': ['mcp:read']   # by JSON-RPC method
        tools:
            delete-project: ['mcp:admin']    # by tool name, for tools/call
        implies:
            'mcp:admin': ['mcp:read']        # a granted mcp:admin also grants mcp:read
```

When the token lacks a required scope, the MCP endpoint answers `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="<required scopes>"`, and the client can start a step-up authorization. Without a token, it answers `401`. Handlers see the expanded scopes in `AccessToken::getScopes()` and `hasScope()`. Add the scopes to League `scopes.available`, and keep `scope_policy.default` empty if the firewall already requires `mcp`.

## Session binding

Clients on protocol versions before 2026-07-28 keep an `Mcp-Session-Id` across requests. With `session_binding: true`, this bundle stores each session of every mcp-bundle server together with a fingerprint of the token's user and OAuth client. A request with a token of another user or client gets `404 Session not found`, the same answer as for an unknown session, so a leaked session id is useless without its owner's token. The same user on another client gets a new session too.

Sessions that existed before you enabled the binding are unknown after it, and clients start a new session once. Set `session_binding: false` only if your MCP server keeps no user data in its sessions.

## DCR hardening

The register endpoint is public, so it only accepts:

- redirect URIs using `https`, loopback `http` (`127.0.0.1`, `[::1]`, `localhost`) or a scheme listed in `dcr.redirect_uri_schemes`; never `javascript:`, `data:`, `file:`, URIs with a fragment or with user info
- at most 10 redirect URIs of at most 2000 characters each
- a `client_name` of at most 200 characters without control characters
- a `scope` of at most 1000 characters (or 50 entries)
- a request body of at most 16 KB

To rate limit registrations per client IP, install `symfony/rate-limiter`, define a limiter and reference it by name:

```yaml
framework:
    rate_limiter:
        mcp_oauth_register:
            policy: sliding_window
            limit: 10
            interval: '1 hour'

mcp_oauth:
    dcr:
        rate_limiter: mcp_oauth_register
```

Over the limit, the endpoint returns `429` with a `Retry-After` header. The limiter keys on `Request::getClientIp()`, so configure Symfony `trusted_proxies` behind a reverse proxy; otherwise every client shares the proxy IP.

## DCR client authentication

The deprecated DCR endpoint accepts both public and confidential clients (both must send an S256 `code_challenge` on MCP authorize requests):

- `token_endpoint_auth_method: none` creates a public PKCE client
- `token_endpoint_auth_method: client_secret_basic` or `client_secret_post` creates a confidential client and returns `client_secret` once in the registration response

League 0.10 stores that secret using its plaintext-compatible repository. League 1.2+ stores a password hash while the DCR response still returns the plain secret required by the client. League does not bind a client to one method: the token endpoint reads the secret from the `Authorization: Basic` header or from the request body, so both methods work for every confidential client.
