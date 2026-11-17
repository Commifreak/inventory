# Configuration

The server is configured with environment variables. Everything else (SMTP,
alert rules, intervals, update policy, users) is configured in the web UI.

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | derived from requests | Public URL, e.g. `https://inventory.example.com`. Written into installers – set it. |
| `TZ` | `UTC` | Time zone for the UI and mails, e.g. `Europe/Berlin`. |
| `INITIAL_ADMIN_PASSWORD` | random | Password of the `admin` user created on first start. If unset, a random password is printed to the log once. It must be changed at first login. |
| `DATA_DIR` | `/data` | Database, encryption key, agent versions, caches. **Back it up.** |
| `LISTEN_ADDR` | `:8080` | HTTP listen address (TLS is expected to be terminated by a reverse proxy). |
| `TRUSTED_PROXIES` | private networks | CIDRs whose `X-Forwarded-*` headers are trusted (client IP, scheme, host). |
| `LOCAL_LOGIN` | `true` | `false` disables password login (requires OIDC). |
| `SESSION_LIFETIME` | `12h` | Idle lifetime of UI sessions (Go duration). |
| `ENCRYPTION_KEY` | generated | Base64 32-byte key for stored secrets (SMTP password). Normally generated in `DATA_DIR/secrets/encryption.key`. |
| `EOL_FETCH` | `true` | Fetch end-of-support dates (OS and Office) from endoflife.date daily (needs outbound HTTPS); a built-in table covers Windows and Office otherwise. Failed fetches are retried hourly; if no fetch succeeded for 3 days (or never, after two attempts) the web UI shows a warning. |
| `LOG_LEVEL` | `info` | `debug` for more output. |
| `OIDC_ISSUER` | – | OpenID Connect issuer URL. Enables single sign-on. |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | – | Client credentials. |
| `OIDC_ADMIN_GROUP` | – | Only members of this group may sign in. Empty = every authenticated user of the client. |
| `OIDC_GROUPS_CLAIM` | `groups` | Claim containing the groups. |
| `OIDC_SCOPES` | `openid profile email groups` | Requested scopes. |
| `OIDC_BUTTON_LABEL` | `Sign in with SSO` | Text of the login button. |

## Reverse proxy (Traefik)

See [`docker-compose.example.yml`](../docker-compose.example.yml). The server
needs no special headers besides the usual `X-Forwarded-For/Proto/Host`.

Agents and installers use only paths below **`/api/agent/`**. If you protect
the UI with a forward-auth middleware, exclude that prefix (second router in
the example), otherwise agents cannot reach the server. With the built-in
OIDC login no middleware is needed.

## Single sign-on

Redirect URI to register at the identity provider:
`https://<your host>/auth/oidc/callback`

All users are administrators; restrict access with `OIDC_ADMIN_GROUP`. Users
are created on their first SSO login. Existing local users are never linked to
SSO accounts automatically (prevents account takeover). Keep one local admin as
emergency access, or set `LOCAL_LOGIN=false` once SSO works.

### Authentik

1. *Applications → Providers → Create → OAuth2/OpenID Provider*: client type
   *Confidential*, redirect URI as above, signing key set.
2. Create an application using this provider, slug e.g. `inventory`.
3. Create a group `inventory-admins` and add your user.
4. Environment:

```yaml
OIDC_ISSUER: https://authentik.example.com/application/o/inventory/
OIDC_CLIENT_ID: <client id>
OIDC_CLIENT_SECRET: <client secret>
OIDC_ADMIN_GROUP: inventory-admins
```

### Authelia

```yaml
# authelia configuration.yml
identity_providers:
  oidc:
    clients:
      - client_id: inventory
        client_name: Inventory
        client_secret: '$pbkdf2-sha512$...'   # authelia crypto hash generate
        authorization_policy: two_factor
        redirect_uris:
          - https://inventory.example.com/auth/oidc/callback
        scopes: [openid, profile, email, groups]
        token_endpoint_auth_method: client_secret_basic
```

```yaml
# inventory environment
OIDC_ISSUER: https://auth.example.com
OIDC_CLIENT_ID: inventory
OIDC_CLIENT_SECRET: <plain secret>
OIDC_ADMIN_GROUP: inventory-admins
```

## Data volume

`/data` contains:

| Path | Content |
|---|---|
| `inventory.db` | SQLite database (WAL mode) |
| `secrets/encryption.key` | key for stored secrets – without it the SMTP password cannot be decrypted |
| `agents/<version>/` | agent binaries; old versions are kept for pinning/rollback (newest 5 + all in use) |
| `eol/` | cached end-of-support data |

The container runs as UID 65532. Named volumes work out of the box; for bind
mounts run `chown -R 65532:65532 <dir>` first.

Backup: stop the container and copy the directory, or use
`sqlite3 inventory.db ".backup backup.db"` while running – and keep `secrets/`.
