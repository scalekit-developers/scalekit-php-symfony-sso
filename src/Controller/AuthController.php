<?php

namespace App\Controller;

use App\Service\LocalUserStore;
use App\Service\ScalekitOidcClient;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
class AuthController
{
    public const MODE_HANDSHAKE = 'handshake';
    public const MODE_MODULAR = 'modular';

    public function __construct(
        private readonly ScalekitOidcClient $scalekit,
        private readonly LocalUserStore $users,
    ) {
    }

    #[Route('/', name: 'home', methods: ['GET'])]
    public function home(Request $request): Response
    {
        if ($this->isSignedIn($request)) {
            return new RedirectResponse('/profile');
        }

        return $this->page('Scalekit Symfony SSO', <<<'HTML'
            <h1>Scalekit Modular SSO</h1>
            <p class="lede">This Symfony app talks to Scalekit over OpenID Connect. There is no PHP SDK. Pick a mode, then complete SSO.</p>

            <div class="grid">
                <section class="card">
                    <h2>Mode A — Handshake only</h2>
                    <p>Send the user to Scalekit with no tenant hint. After login, the app stores the verified <code>id_token</code> claims in the session.</p>
                    <p>Use this to see the raw OIDC path.</p>
                    <a class="button" href="/login?mode=handshake">Log in with Scalekit</a>
                </section>

                <section class="card">
                    <h2>Mode B — Modular SSO</h2>
                    <p>Tell Scalekit which org or connection to use. After login, the app finds or creates a <strong>local</strong> user by email. The session stores that local id, not Scalekit <code>sub</code>.</p>
                    <p>Use this when your app already owns user accounts.</p>
                    <form action="/login" method="get">
                        <input type="hidden" name="mode" value="modular">
                        <label>Email (sent as <code>login_hint</code>)
                            <input name="email" type="email" placeholder="you@company.com">
                        </label>
                        <label>or Organization ID
                            <input name="organization_id" placeholder="org_123">
                        </label>
                        <label>or Connection ID
                            <input name="connection_id" placeholder="conn_123">
                        </label>
                        <button type="submit">Continue with Modular SSO</button>
                    </form>
                    <p class="hint">Scalekit reads these in order: <code>connection_id</code>, then <code>organization_id</code>, then <code>login_hint</code>. Send one.</p>
                </section>
            </div>
            HTML);
    }

    #[Route('/login', name: 'login', methods: ['GET'])]
    public function login(Request $request): Response
    {
        $mode = $request->query->get('mode', self::MODE_MODULAR);
        $ssoParams = [];

        if ($mode === self::MODE_MODULAR) {
            $connectionId = $request->query->get('connection_id') ?: null;
            $organizationId = $request->query->get('organization_id') ?: null;
            $email = $request->query->get('email') ?: null;

            if ($connectionId !== null) {
                $ssoParams['connection_id'] = $connectionId;
            } elseif ($organizationId !== null) {
                $ssoParams['organization_id'] = $organizationId;
            } elseif ($email !== null && str_contains($email, '@')) {
                $ssoParams['login_hint'] = $email;
            } else {
                return $this->page('Choose a routing value', <<<'HTML'
                    <h1>Mode B needs a routing value</h1>
                    <p>Provide an email, an <code>organization_id</code>, or a <code>connection_id</code> so Scalekit can pick the right identity provider.</p>
                    <p><a href="/">Back to home</a></p>
                    HTML, 400);
            }
        } elseif ($mode !== self::MODE_HANDSHAKE) {
            return $this->page('Unknown mode', '<h1>Unknown mode</h1><p>Use <code>handshake</code> or <code>modular</code>.</p><p><a href="/">Back to home</a></p>', 400);
        }

        $state = bin2hex(random_bytes(16));
        $session = $request->getSession();
        $session->set('oauth_state', $state);
        $session->set('login_mode', $mode);

        return new RedirectResponse($this->scalekit->buildAuthorizationUrl($state, $ssoParams));
    }

    #[Route('/callback', name: 'callback', methods: ['GET'])]
    public function callback(Request $request): Response
    {
        $session = $request->getSession();
        $expectedState = $session->get('oauth_state');
        $session->remove('oauth_state');

        if ($expectedState === null || $request->query->get('state') !== $expectedState) {
            return $this->page('Invalid state', '<h1>Invalid or missing state</h1><p>Start login again from the home page.</p><p><a href="/">Back to home</a></p>', 400);
        }

        $code = $request->query->get('code');
        if ($code === null) {
            $error = htmlspecialchars((string) $request->query->get('error', 'unknown'), ENT_QUOTES);
            return $this->page('Missing code', "<h1>Missing authorization code</h1><p>Error: {$error}</p><p><a href=\"/\">Back to home</a></p>", 400);
        }

        $claims = $this->scalekit->exchangeCodeForClaims($code);
        $mode = $session->get('login_mode', self::MODE_HANDSHAKE);

        if ($mode === self::MODE_MODULAR) {
            $email = $claims['email'] ?? null;
            if ($email === null) {
                return $this->page('Missing email', '<h1>id_token did not include an email claim</h1><p><a href="/">Back to home</a></p>', 400);
            }

            $user = $this->users->findOrCreateByEmail(
                $email,
                (string) ($claims['oid'] ?? ''),
                (string) (($claims['amr'] ?? [])[0] ?? ''),
            );
            $session->set('local_user_id', $user['id']);
            $session->remove('user_claims');
        } else {
            $session->set('user_claims', $claims);
            $session->remove('local_user_id');
        }

        return new RedirectResponse('/profile');
    }

    #[Route('/profile', name: 'profile', methods: ['GET'])]
    public function profile(Request $request): Response
    {
        $session = $request->getSession();
        $mode = $session->get('login_mode');

        if ($mode === self::MODE_MODULAR) {
            $userId = $session->get('local_user_id');
            if ($userId === null) {
                return new RedirectResponse('/');
            }

            $user = $this->users->find((int) $userId);
            if ($user === null) {
                return new RedirectResponse('/');
            }

            $email = htmlspecialchars($user['email'], ENT_QUOTES);
            $orgId = htmlspecialchars($user['scalekit_organization_id'], ENT_QUOTES);
            $connId = htmlspecialchars($user['scalekit_connection_id'], ENT_QUOTES);
            $localId = htmlspecialchars((string) $user['id'], ENT_QUOTES);

            return $this->page('Profile', <<<HTML
                <p class="badge">Mode B — Modular SSO</p>
                <h1>Welcome, {$email}</h1>
                <p>Local user id <code>{$localId}</code> is owned by this app, not by Scalekit.</p>
                <dl>
                    <dt>Scalekit organization</dt><dd><code>{$orgId}</code></dd>
                    <dt>Scalekit connection</dt><dd><code>{$connId}</code></dd>
                </dl>
                <p><a href="/logout">Log out</a></p>
                HTML);
        }

        $claims = $session->get('user_claims');
        if (!is_array($claims)) {
            return new RedirectResponse('/');
        }

        $email = htmlspecialchars((string) ($claims['email'] ?? 'unknown'), ENT_QUOTES);
        $name = htmlspecialchars((string) ($claims['name'] ?? $claims['preferred_username'] ?? $email), ENT_QUOTES);
        $sub = htmlspecialchars((string) ($claims['sub'] ?? ''), ENT_QUOTES);
        $oid = htmlspecialchars((string) ($claims['oid'] ?? ''), ENT_QUOTES);

        return $this->page('Profile', <<<HTML
            <p class="badge">Mode A — Handshake only</p>
            <h1>Welcome, {$name}</h1>
            <p>This session stores verified <code>id_token</code> claims. There is no local user row.</p>
            <dl>
                <dt>Email</dt><dd>{$email}</dd>
                <dt>Subject</dt><dd><code>{$sub}</code></dd>
                <dt>Organization</dt><dd><code>{$oid}</code></dd>
            </dl>
            <p><a href="/logout">Log out</a></p>
            HTML);
    }

    #[Route('/logout', name: 'logout', methods: ['GET'])]
    public function logout(Request $request): RedirectResponse
    {
        $request->getSession()->clear();

        return new RedirectResponse('/');
    }

    private function isSignedIn(Request $request): bool
    {
        $session = $request->getSession();

        return $session->get('local_user_id') !== null || $session->get('user_claims') !== null;
    }

    private function page(string $title, string $body, int $status = 200): Response
    {
        $safeTitle = htmlspecialchars($title, ENT_QUOTES);

        return new Response(<<<HTML
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>{$safeTitle}</title>
                <style>
                    :root { color-scheme: light dark; }
                    body { font: 16px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 52rem; padding: 2rem 1.25rem; }
                    h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
                    h2 { font-size: 1.15rem; margin-top: 0; }
                    .lede { color: CanvasText; opacity: 0.85; }
                    .grid { display: grid; gap: 1rem; margin-top: 1.5rem; }
                    @media (min-width: 720px) { .grid { grid-template-columns: 1fr 1fr; } }
                    .card { border: 1px solid color-mix(in srgb, CanvasText 18%, transparent); border-radius: 12px; padding: 1.1rem 1.15rem; }
                    label { display: block; margin: 0.65rem 0; }
                    input { display: block; width: 100%; box-sizing: border-box; margin-top: 0.25rem; padding: 0.45rem 0.5rem; }
                    .button, button { display: inline-block; margin-top: 0.5rem; padding: 0.5rem 0.8rem; border-radius: 8px; border: 0; background: #111; color: #fff; text-decoration: none; cursor: pointer; }
                    .hint { font-size: 0.9rem; opacity: 0.75; }
                    .badge { display: inline-block; font-size: 0.8rem; letter-spacing: 0.02em; text-transform: uppercase; opacity: 0.7; }
                    dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.35rem 1rem; }
                    dt { font-weight: 600; }
                    code { font-size: 0.92em; }
                </style>
            </head>
            <body>{$body}</body>
            </html>
            HTML, $status);
    }
}
