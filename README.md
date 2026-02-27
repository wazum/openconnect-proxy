# openconnect + tinyproxy + microsocks

This Docker image contains an [openconnect client](http://www.infradead.org/openconnect/) (recent version with pulse/juniper support) and the [tinyproxy proxy server](https://tinyproxy.github.io/) for http/https connections (default on port 8888) and the [microsocks proxy](https://github.com/rofl0r/microsocks) for socks5 connections (default on port 8889) in a small [alpine linux](https://www.alpinelinux.org/) image (around 80 MB).

```sh
OpenConnect version v9.12
Using OpenSSL 3.1.8 11 Feb 2025. Features present: TPM (OpenSSL ENGINE not present), RSA software token, HOTP software token, TOTP software token, Yubikey OATH, DTLS, ESP
Supported protocols: anyconnect (default), nc, gp, pulse, f5, fortinet, array
```

You can find the image on docker hub:
https://hub.docker.com/r/wazum/openconnect-proxy

# Requirements

If you don't want to set the environment variables on the command line
set the environment variables in a `.env` file:

```sh
OPENCONNECT_URL=<gateway URL>
OPENCONNECT_USER=<username>
OPENCONNECT_PASSWORD=<password>
OPENCONNECT_OPTIONS=--authgroup <VPN group> \
	--servercert <VPN server certificate> --protocol=<Protocol> \
	--reconnect-timeout 86400
VPN_SPLIT=0
```

(available protocols, see above)

_Don't use quotes around the values!_

See the [openconnect documentation](https://www.infradead.org/openconnect/manual.html) for available options. 

Either set the password in the `.env` file or leave the variable `OPENCONNECT_PASSWORD` unset, so you get prompted when starting up the container.

Optionally set a TOTP secret to auto-generate MFA codes:

```sh
OPENCONNECT_TOTP_SECRET=<TOTP base32 secret>
```

Or provide a one-time MFA code directly:

```sh
OPENCONNECT_MFA_CODE=<Multi factor authentication code>
```

# Run container in foreground

To start the container in foreground run:

```sh
docker run -it --rm --privileged --env-file=.env \
  -p 8888:8888 -p 8889:8889 wazum/openconnect-proxy:latest
```

The proxies are listening on ports 8888 (http/https) and 8889 (socks). Either use `--net host` or `-p <local port>:8888 -p <local port>:8889` to make the proxy ports available on the host.

Without using a `.env` file set the environment variables on the command line with the docker run option `-e`:

```sh
docker run … -e OPENCONNECT_URL=vpn.gateway.com/example \
-e OPENCONNECT_OPTIONS='<Openconnect Options>' \
-e OPENCONNECT_USER=<Username> …
```

# Run container in background

To start the container in daemon mode (background) set the `-d` option:

```sh
docker run -d -it --rm …
```

In daemon mode you can view the stderr log with `docker logs`:

```sh
docker logs `docker ps|grep "wazum/openconnect-proxy"|awk -F' ' '{print $1}'`
```

# Use container with docker-compose

```yaml
vpn:
  container_name: openconnect_vpn
  image: wazum/openconnect-proxy:latest
  privileged: true
  env_file:
    - .env
  ports:
    - 8888:8888
    - 8889:8889
  cap_add:
    - NET_ADMIN
  networks:
    - mynetwork
```

Set the environment variables for _openconnect_ in the `.env` file again (or specify another file) and 
map the configured ports in the container to your local ports if you want to access the VPN 
on the host too when running your containers. Otherwise only the docker containers in the same
network have access to the proxy ports.

# Route traffic through VPN container

Let's say you have a `vpn` container defined as above, then add `network_mode` option to your other containers:

```yaml
depends_on:
  - vpn
network_mode: "service:vpn"
```

Keep in mind that `networks`, `extra_hosts`, etc. and `network_mode` are mutually exclusive!

# vpn-slice

If you want to route only specific traffic through the VPN container you can use [vpn-slice](https://github.com/dlenski/vpn-slice/).

Set this in your `.env` file:

```sh
VPN_SPLIT=1
VPN_ROUTES=172.16.0.0/12 XXX.XXX.XXX.XXX/32
```

# Configure proxy

The container is connected via _openconnect_ and now you can configure your browser
and other software to use one of the proxies (8888 for http/https or 8889 for socks).

For example FoxyProxy (available for Firefox, Chrome) is a suitable browser extension.

You may also set environment variables:

```sh
export http_proxy="http://127.0.0.1:8888/"
export https_proxy="http://127.0.0.1:8888/"
```

composer, git (if you don't use the git+ssh protocol, see below) and others use these.

# ssh through the proxy

You need nc (netcat), corkscrew or something similar to make this work.

Unfortunately some git clients (e.g. Gitkraken) don't use the settings from ssh config
and you can't pull/push from a repository that's reachable (DNS resolution) only through VPN.

## nc (netcat, ncat)

Set a `ProxyCommand` in your `~/.ssh/config` file like

```
Host <hostname>
     ProxyCommand   nc -x 127.0.0.1:8889 %h %p
```

or (depending on your ncat version)

```
Host <hostname>
     ProxyCommand   ncat --proxy 127.0.0.1:8889 --proxy-type socks5 %h %p
```

and your connection will be passed through the proxy.
The above example is for using git with ssh keys.

## corkscrew 

An alternative is _corkscrew_ (e.g. install with `brew install corkscrew` on mac OS)

```
Host <hostname>
     ProxyCommand   corkscrew 127.0.0.1 8888 %h %p
```

## Multiple jump hosts

You can add multiple jump hosts in your `~/.ssh/config` file with `corkscrew` etc. like:

```
Host admin-proxy
    ProxyCommand corkscrew 127.0.0.1 8888 %h %p

Host actual-host
    User someuser
    ProxyJump admin-proxy
```

```
$ ssh user@actual-host

Local Machine               HTTP PROXY           JUMP HOST           TARGET
+----------------+          (TinyProxy)          (admin-proxy)       (actual-host)
|                |          
|  SSH Client    |         127.0.0.1:8888    
|  ~/.ssh/config |               +                    +                   +
|  + corkscrew   |               |                    |                   |
|                +-------------->|                    |                   |
|                |               |                    |                   |
+----------------+               |                    |                   |
                                 +------------------->|                   |
                                                      |                   |
                                                      +------------------>|

- SSH + Corkscrew -----> TinyProxy (8888)
- TinyProxy -----------> admin-proxy
- admin-proxy ---------> actual-host (as someuser)
```

# SAML/SSO Authentication (Microsoft Entra ID, Okta, etc.)

For VPN gateways that use browser-based SAML/OAuth authentication, this project provides a **sidecar auth helper** that automates the login flow using headless Chromium via Playwright.

The sidecar pattern keeps the main VPN image small (~80 MB). The auth helper runs once to obtain a session cookie, then exits.

## Built-in providers

| Provider | `VPN_AUTH_PROVIDER` | Covers |
|---|---|---|
| **Microsoft Entra ID** | `microsoft` (default) | Azure AD, ADFS, M365 SSO |
| **Okta** | `okta` | Okta Classic Engine, Okta Identity Engine (OIE) |
| **Generic** | `generic` | Fallback using common HTML form patterns |

Each provider is a YAML config defining form selectors, button labels, and cookie names. See `auth/providers/` for details.

## Setup

1. Set environment variables in your `.env` file:

```sh
VPN_URL=https://vpn.example.com
VPN_USER=user@company.com
VPN_PASSWORD=your-password
VPN_PROTOCOL=anyconnect
VPN_AUTH_PROVIDER=microsoft
VPN_TOTP_SECRET=YOUR_BASE32_TOTP_SECRET
```

`VPN_TOTP_SECRET` is optional — only needed if your IdP requires TOTP-based MFA. You can extract the TOTP secret from your authenticator app setup (the base32 string shown during QR code enrollment).

2. Run with Docker Compose:

```sh
docker compose -f docker-compose.saml.yml --env-file .env up
```

The `saml-auth` container launches headless Chromium, completes the login flow, extracts the VPN session cookie, and writes it to a shared volume. The `vpn` container then starts OpenConnect using that cookie.

## Custom provider config

If the built-in presets don't work for your IdP, create a custom YAML config:

```yaml
name: My Corporate IdP
saml_paths:
  anyconnect: "/saml/login"
fields:
  username:
    ids: [login-email]
    labels: [Email]
    types: [email]
  password:
    ids: [login-password]
    types: [password]
  otp:
    ids: [mfa-code]
    labels: [Verification code]
buttons:
  next:
    labels: [Continue]
    selectors: ["button[type=submit]"]
  sign_in:
    labels: [Sign In]
    selectors: ["button[type=submit]"]
  verify:
    labels: [Verify]
prompts:
  stay_signed_in:
    detect: [Stay signed in]
    click: ["Yes"]
cookies:
  anyconnect: [webvpn, SVPNCOOKIE]
```

Mount it and set `VPN_AUTH_CONFIG`:

```sh
docker run --rm \
  -e VPN_URL=vpn.example.com \
  -e VPN_USER=user@company.com \
  -e VPN_PASSWORD=secret \
  -e VPN_AUTH_CONFIG=/app/custom-provider.yaml \
  -v ./my-provider.yaml:/app/custom-provider.yaml:ro \
  -v /tmp/auth:/auth \
  your-auth-image
```

## Manual cookie mode

If you obtain a VPN cookie through other means (browser developer tools, another script), you can pass it directly without the auth helper:

```sh
docker run -it --rm --privileged \
  -e OPENCONNECT_URL=vpn.example.com \
  -e OPENCONNECT_COOKIE="webvpn=ABC123..." \
  -e OPENCONNECT_OPTIONS="--protocol=anyconnect" \
  -p 8888:8888 -p 8889:8889 \
  wazum/openconnect-proxy:latest
```

## TLS / Custom CA certificates

If your VPN gateway uses a private CA or self-signed certificate, mount the CA cert into the auth container:

```sh
docker run --rm \
  -v ./corporate-ca.crt:/usr/local/share/ca-certificates/corporate-ca.crt:ro \
  -e VPN_URL=vpn.example.com \
  ...
  your-auth-image
```

The entrypoint automatically runs `update-ca-certificates` when certs are found in that directory.

As a last resort for testing only, you can disable TLS validation entirely with `AUTH_IGNORE_TLS_ERRORS=1`. **Do not use this in production** — it exposes your IdP credentials to man-in-the-middle attacks.

## Debugging

Set `AUTH_DEBUG=1` for verbose logging and screenshots saved to `/tmp/saml-step-*.png`:

```sh
docker run --rm -e AUTH_DEBUG=1 -e VPN_URL=... -v /tmp:/tmp your-auth-image
```

## Environment variables (SAML auth helper)

| Variable | Required | Description |
|---|---|---|
| `VPN_URL` | Yes | VPN gateway URL |
| `VPN_USER` | Yes | IdP username |
| `VPN_PASSWORD` | Yes | IdP password |
| `VPN_PROTOCOL` | No | `anyconnect` (default) or `globalprotect` |
| `VPN_AUTH_PROVIDER` | No | Built-in preset: `microsoft` (default), `okta`, `generic` |
| `VPN_AUTH_CONFIG` | No | Path to custom provider YAML (overrides `VPN_AUTH_PROVIDER`) |
| `VPN_TOTP_SECRET` | No | TOTP base32 secret for MFA auto-fill |
| `AUTH_TIMEOUT` | No | Override provider timeout in seconds |
| `AUTH_DEBUG` | No | Set to `1` for debug screenshots and verbose logging |
| `AUTH_IGNORE_TLS_ERRORS` | No | Set to `1` to disable TLS validation (**testing only**) |

# CI/CD Pipelines with VPN + MFA

Deployment targets often sit behind a VPN that requires MFA. This makes CI/CD pipelines tricky — a GitLab Runner or GitHub Actions workflow can't tap a push notification or type a TOTP code.

### Requirements

- **Self-hosted GitLab Runner** with Docker executor and `privileged = true` in `config.toml` — GitLab SaaS shared runners do not allow privileged containers
- **Docker-in-Docker** (`docker:dind`) service — the VPN container needs `--privileged` for OpenConnect to create the tun0 interface
- Split tunneling (`VPN_SPLIT=1`) is not supported in CI/CD — routing table changes don't propagate through Docker network namespaces. Use proxy-based access instead (`http_proxy` / `https_proxy`)

There are two approaches depending on how the VPN authenticates:

1. **Password + MFA** (standard) — OpenConnect handles authentication directly via `OPENCONNECT_PASSWORD` and `OPENCONNECT_TOTP_SECRET` (or `OPENCONNECT_MFA_CODE`). No sidecar needed.
2. **SAML/SSO + MFA** — The VPN gateway redirects to a browser-based IdP login (Microsoft Entra, Okta, etc.). Use the auth sidecar to automate the browser flow.

In both cases, use a **CI service account with TOTP-based MFA** so the code can be generated automatically.

## MFA compatibility

Not all MFA methods can be automated. Ask the client to enable **TOTP** for the CI service account:

| MFA Method | Automated? | Notes |
|---|---|---|
| TOTP (Google Authenticator, MS Authenticator code mode) | Yes | Set `OPENCONNECT_TOTP_SECRET` or `VPN_TOTP_SECRET` |
| Push notification (MS Authenticator, Okta Verify) | No | Requires human tap |
| Number matching (MS Entra) | No | Requires human input |
| SMS code | No | Requires phone access |
| Hardware token (YubiKey, RSA) | No | Requires physical device |

## Standard auth (password + MFA code)

When the VPN gateway accepts username/password directly (no browser redirect), you only need the VPN proxy image:

```
┌──────────────┐      ┌──────────────┐      ┌─────────────────┐
│  CI Runner   │─────>│  VPN Proxy   │─────>│ Internal Server │
│ (GitLab/GH)  │      │ (openconnect │      │  (behind VPN)   │
│              │      │ + tinyproxy) │      │                 │
└──────────────┘      └──────────────┘      └─────────────────┘

1. Start VPN container with OPENCONNECT_TOTP_SECRET
2. openconnect authenticates with password + auto-generated TOTP
3. Deploy commands routed through http_proxy
```

Set `OPENCONNECT_TOTP_SECRET` and the container generates the TOTP code automatically — no extra tools needed in your pipeline. See [`examples/gitlab-ci.saml.yml`](examples/gitlab-ci.saml.yml) — the "Standard auth" job shows this approach.

## SAML/SSO auth (browser-based login)

When the VPN gateway redirects to a SAML IdP, the auth sidecar automates the browser flow:

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐      ┌─────────────────┐
│  CI Runner   │─────>│  SAML Auth   │─────>│  VPN Proxy   │─────>│ Internal Server │
│ (GitLab/GH)  │      │  (headless   │      │ (openconnect │      │  (behind VPN)   │
│              │      │   browser)   │      │ + tinyproxy) │      │                 │
└──────────────┘      └──────────────┘      └──────────────┘      └─────────────────┘

1. Run auth sidecar with VPN_TOTP_SECRET
2. Headless browser completes SAML login + auto TOTP --> cookie.json
3. VPN container connects with session cookie
4. Deploy commands routed through http_proxy
```

The sidecar generates the TOTP code automatically via `VPN_TOTP_SECRET` and writes a session cookie that the VPN container picks up. See [`examples/gitlab-ci.saml.yml`](examples/gitlab-ci.saml.yml) — the "SAML auth" job shows this approach.

## GitLab CI example

Configure these as **masked CI/CD variables** (Settings > CI/CD > Variables):

| Variable | Required | Description |
|---|---|---|
| `VPN_URL` | Yes | VPN gateway URL |
| `VPN_USER` | Yes | VPN / IdP username |
| `VPN_PASSWORD` | Yes | VPN / IdP password |
| `VPN_TOTP_SECRET` | No | TOTP base32 secret — the example maps this to `OPENCONNECT_TOTP_SECRET` (standard) or `VPN_TOTP_SECRET` (SAML) |
| `VPN_PROTOCOL` | No | `anyconnect` (default) or `globalprotect` |
| `VPN_AUTH_PROVIDER` | SAML only | `microsoft` (default), `okta`, or `generic` |

See [`examples/gitlab-ci.saml.yml`](examples/gitlab-ci.saml.yml) for ready-to-use job definitions covering both auth modes.

## GitHub Actions

The same pattern works with GitHub Actions — use Docker commands in `run` steps and store secrets in repository settings. The container workflow is identical.

# Security

A security audit of the codebase was performed on 2026-02-27, covering command injection, input validation, path traversal, credential exposure, and authentication bypass categories. No exploitable vulnerabilities were found. All environment variables (`OPENCONNECT_*`, `VPN_*`, `PROXY_PORT`, etc.) are trusted operator-controlled inputs and are not exposed to untrusted user input at runtime.

# Build

You can build the container yourself with:

```sh
docker build -f build/Dockerfile -t wazum/openconnect-proxy:custom ./build
```

# Support

You like using my work? Get something for me (surprise! surprise!) from my wishlist on [Amazon](https://smile.amazon.de/hz/wishlist/ls/307SIOOD654GF/) or [help me pay](https://www.paypal.me/wazum) the next pizza or Pho soup (mjam). Thanks a lot!
