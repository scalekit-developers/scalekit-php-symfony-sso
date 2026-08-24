# Scalekit Modular SSO for PHP Symfony

This sample adds enterprise Single Sign-On (SSO) to a Symfony app by calling Scalekit OpenID Connect (OIDC) endpoints directly. There is no official PHP SDK.

The app is Modular SSO, not SaaSKit / Full Stack Auth. Scalekit proves the user's identity. This app owns the session, and in Mode B it also owns the user record.

## Two modes on one home page

Open `http://localhost:8000` and pick a mode.

| Mode | What you send to Scalekit | What the app stores after login | Use this when |
|------|---------------------------|----------------------------------|---------------|
| **A — Handshake only** | Client id, redirect, scope, and `state`. No tenant hint. | Verified `id_token` claims in the session | You want to see the raw OIDC path |
| **B — Modular SSO** | One of `connection_id`, `organization_id`, or `login_hint` | A **local** user row, keyed by email. Session holds that local id, not Scalekit `sub` | Your product already has users and tenants |

Scalekit reads Mode B values in this order: `connection_id` first, then `organization_id`, then `login_hint`.

[Modular SSO guide](https://docs.scalekit.com/authenticate/sso/add-modular-sso/)

## What you need

- PHP 8.1 or later
- [Composer](https://getcomposer.org/)
- A Scalekit workspace with **Full-Stack Auth turned off** (Modular Auth)

## Configure Scalekit

Do these steps in the [Scalekit dashboard](https://app.scalekit.com) before you run the app.

1. Open **Authentication → General**.
2. Disable **Full-Stack Auth**. That turns on Modular SSO.
3. Copy **Environment URL**, **Client ID**, and **Client Secret** from **Developers → API credentials**.
4. Register this callback URL: `http://localhost:8000/callback`.
5. Note a test `organization_id` or `connection_id`. Your environment includes a test org with domains like `@example.com`.

## Run the app

```bash
composer install
cp .env.example .env
```

Edit `.env`:

```env
SCALEKIT_ENVIRONMENT_URL=https://your-env.scalekit.com
SCALEKIT_CLIENT_ID=skc_...
SCALEKIT_CLIENT_SECRET=...
SCALEKIT_REDIRECT_URI=http://localhost:8000/callback
```

Start the server:

```bash
php -S localhost:8000 -t public
```

Open [http://localhost:8000](http://localhost:8000).

## Try Mode A

1. Click **Log in with Scalekit**.
2. Complete SSO in Scalekit (use the IdP simulator if you have no real IdP yet).
3. Land on `/profile`. The page shows claims from the verified `id_token`.

Mode A does not create a local user. The session is the token claims.

## Try Mode B

1. Enter one value: an email such as `dev@example.com`, or an `organization_id`, or a `connection_id`.
2. Click **Continue with Modular SSO**.
3. Complete SSO.
4. Land on `/profile`. The page shows a local user id plus the Scalekit org and connection that signed the user in.

Log in again with the same email. The local id stays the same. That is the point: this app owns the user table.

## How the code works

```
GET /login
  → Scalekit /oauth/authorize
  → customer IdP
  → GET /callback?code=...&state=...
  → POST /oauth/token
  → verify id_token with JWKS
  → Mode A: store claims
    Mode B: find or create local user by email
  → GET /profile
```

| File | Role |
|------|------|
| `src/Service/ScalekitOidcClient.php` | Discovery, authorize URL, code exchange, JWKS verify |
| `src/Service/LocalUserStore.php` | JSON stand-in for your user table (Mode B) |
| `src/Controller/AuthController.php` | Home, login, callback, profile, logout |

Replace `LocalUserStore` with your real user repository. Do not use Scalekit `sub` as your primary key.

## Routes

| Route | Purpose |
|-------|---------|
| `GET /` | Mode picker. Redirects to `/profile` if already signed in |
| `GET /login?mode=handshake` | Mode A |
| `GET /login?mode=modular&email=` | Mode B via `login_hint` |
| `GET /login?mode=modular&organization_id=` | Mode B via organization |
| `GET /login?mode=modular&connection_id=` | Mode B via connection |
| `GET /callback` | Exchanges `code`, verifies token, writes the session |
| `GET /profile` | Shows claims (A) or the local user (B) |
| `GET /logout` | Clears the session |

## Tests

```bash
composer test
```

The tests check authorization-URL building for both modes against a mocked discovery document. They do not run a live token exchange. Use a sandbox environment for a full login.

## Common errors

**Invalid redirect_uri**  
Register `http://localhost:8000/callback` on the Scalekit app. The value must match `.env` exactly.

**Organization not found**  
Mode B needs a real `organization_id`, `connection_id`, or an email whose domain is on a Scalekit organization.

**Mode B asks for a routing value**  
Send one of the three fields. Empty form submits fail on purpose.

**Token verification fails**  
Check `SCALEKIT_ENVIRONMENT_URL`. Discovery and JWKS must come from the same environment as the client.

## This sample does not cover

- SaaSKit / Full Stack Auth (hosted login, Scalekit-owned users). See the [Laravel FSA example](https://github.com/scalekit-inc/scalekit-laravel-auth-example).
- A PHP SDK. Use the OIDC client in this repo.
- Admin portal embedding or SCIM.

## License

MIT. See [LICENSE](LICENSE).
