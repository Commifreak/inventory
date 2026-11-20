# Configuration

The server is configured with environment variables. Everything else (SMTP,
alert rules, intervals, update policy, users) is configured in the web UI.

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | derived from requests | Public URL, e.g. `https://inventory.example.com` (without a reverse proxy `http://SERVER-IP:8080`). Written into installers – set it. With `https://` the session cookie is marked Secure: sign in via that HTTPS address, not via `http://`. |
| `TZ` | `UTC` | Time zone for the UI and mails, e.g. `Europe/Berlin`. |
| `INITIAL_ADMIN_PASSWORD` | random | Password of the `admin` user created on first start. If unset, a random password is printed to the log once. It must be changed at first login. |
| `DATA_DIR` | `/data` | Database, encryption key, agent versions, caches. **Back it up.** |
| `LISTEN_ADDR` | `:8080` | HTTP listen address (TLS is expected to be terminated by a reverse proxy). |
| `TRUSTED_PROXIES` | private networks | CIDRs whose `X-Forwarded-*` headers are trusted (client IP, scheme, host). |
| `LOCAL_LOGIN` | `true` | `false` disables password login (requires OIDC). |
| `SESSION_LIFETIME` | `12h` | Idle lifetime of UI sessions (Go duration). |
| `ENCRYPTION_KEY` | generated | Base64 32-byte key for stored secrets (SMTP password). Normally generated in `DATA_DIR/secrets/encryption.key`. |
| `HA_ADDON_REPOSITORY` | `https://github.com/Commifreak/inventory-ha-addon` | Home Assistant add-on repository shown on the install page (empty: hide the section). |
| `EOL_FETCH` | `true` | Fetch end-of-support dates (OS and Office) from endoflife.date daily (needs outbound HTTPS) and cache them in `DATA_DIR/eol`; without data end of support is not checked. Failed fetches are retried hourly; if no fetch succeeded for 3 days (or never, after two attempts) the web UI shows a warning. |
| `LOG_LEVEL` | `info` | `debug` for more output. |
| `OIDC_ISSUER` | – | OpenID Connect issuer URL. Enables single sign-on. |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | – | Client credentials. |
| `OIDC_ADMIN_GROUP` | – | Members of this group are superadmins (synchronised at every login). Other SSO users need a group set on an area (or a manually assigned area). Empty: superadmin rights of SSO users are managed in the UI. |
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

Members of `OIDC_ADMIN_GROUP` are superadmins. Other users get access through
**areas**: set a group on an area (*Settings → Areas*, e.g. `inventory-family`)
and its members see and manage the devices and enrollment tokens of that area.
Users are created on their first SSO login if a group grants them access;
superadmin rights and group areas are synchronised at every login (changes in
the identity provider apply at the next login, at the latest after
`SESSION_LIFETIME`). Areas can also be assigned manually under *Settings →
Users*; those are kept. The group name is compared with the `OIDC_GROUPS_CLAIM`
claim (Authelia and Authentik send group names, Entra ID group IDs).

Existing local users are never linked to SSO accounts automatically (prevents
account takeover). Keep one local admin as emergency access, or set
`LOCAL_LOGIN=false` once SSO works.

Upgrading from a version without areas: all devices and tokens are in the
area "Default" and all existing users are superadmins. New SSO users without a
matching group are no longer admitted when `OIDC_ADMIN_GROUP` is empty.

### Authentik

1. *Applications → Providers → Create → OAuth2/OpenID Provider*: client type
   *Confidential*, redirect URI (strict) `https://<your host>/auth/oidc/callback`,
   a signing key selected (RS256), scopes `openid`, `email`, `profile` (the
   default *profile* mapping includes the `groups` claim).
2. Create an application using this provider, slug e.g. `inventory`.
3. Create a group `inventory-admins` and add your user (superadmins). For areas,
   create further groups (e.g. `inventory-family`) and add their members
   directly (the default mapping only sends direct memberships).
4. Environment (`BASE_URL` must be set to the public address):

```yaml
OIDC_ISSUER: https://authentik.example.com/application/o/inventory/   # "OpenID Configuration Issuer" of the provider
OIDC_CLIENT_ID: <client id>
OIDC_CLIENT_SECRET: <client secret>
OIDC_ADMIN_GROUP: inventory-admins
OIDC_SCOPES: openid profile email     # Authentik has no "groups" scope
OIDC_BUTTON_LABEL: Sign in with Authentik
```

If Traefik protects the host with Authentik's forward auth (outpost), exclude
`/api/agent/` from the middleware – agents cannot log in.

### Authelia

```yaml
# Authelia configuration.yml (4.38+)
identity_providers:
  oidc:
    clients:
      - client_id: inventory
        client_name: Inventory
        client_secret: '$pbkdf2-sha512$310000$...'   # authelia crypto hash generate pbkdf2 --random
        public: false
        authorization_policy: two_factor              # or one_factor
        consent_mode: implicit                         # no consent page on every login
        redirect_uris:
          - https://inventory.example.com/auth/oidc/callback
        scopes: [openid, profile, email, groups]
        response_types: [code]
        grant_types: [authorization_code]
        token_endpoint_auth_method: client_secret_basic
```

```yaml
# inventory environment (BASE_URL must be the public address)
OIDC_ISSUER: https://auth.example.com          # Authelia's own URL
OIDC_CLIENT_ID: inventory
OIDC_CLIENT_SECRET: <plain secret>             # the random secret, not the hash
OIDC_ADMIN_GROUP: inventory-admins             # Authelia group (users file / LDAP)
OIDC_BUTTON_LABEL: Sign in with Authelia
```

`OIDC_SCOPES` keeps its default (`openid profile email groups`). Groups, user name
and e-mail are read from the ID token or, if missing there (Authelia 4.39+), from
the userinfo endpoint. If Traefik protects the host with Authelia's forward auth,
exclude `/api/agent/` from the middleware – agents cannot log in.

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
