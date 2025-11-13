#!/usr/bin/env python3
"""Provider-based SAML/OAuth auth engine for OpenConnect VPN.

Reads a declarative YAML provider config (Microsoft, Okta, or custom) and
drives headless Chromium through the login flow to extract session cookies.

Env vars:
    VPN_URL             - VPN gateway URL (required)
    VPN_USER            - IdP username (required)
    VPN_PASSWORD        - IdP password (required)
    VPN_TOTP_SECRET     - TOTP secret for MFA auto-fill (optional)
    VPN_PROTOCOL        - anyconnect (default) or globalprotect
    VPN_AUTH_PROVIDER   - Built-in preset: microsoft, okta, generic (default: microsoft)
    VPN_AUTH_CONFIG     - Path to custom provider YAML (overrides VPN_AUTH_PROVIDER)
    AUTH_OUTPUT_FILE    - Write cookie JSON to this path (default: /auth/cookie.json)
    AUTH_TIMEOUT        - Override provider timeout in seconds
    AUTH_DEBUG          - Set to 1 for debug screenshots and verbose logging
"""

import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright


def log(msg):
    print(f"[saml-auth] {msg}", file=sys.stderr)


def debug(msg):
    if os.environ.get("AUTH_DEBUG") == "1":
        print(f"[saml-auth][DEBUG] {msg}", file=sys.stderr)


def get_totp_code(secret):
    import pyotp

    return pyotp.TOTP(secret).now()


def load_provider(provider_name, custom_path=None):
    if custom_path and os.path.isfile(custom_path):
        log(f"Loading custom provider config: {custom_path}")
        with open(custom_path) as f:
            return yaml.safe_load(f)

    providers_dir = Path(__file__).parent / "providers"
    path = providers_dir / f"{provider_name}.yaml"
    if not path.exists():
        log(f"Provider '{provider_name}' not found, falling back to 'generic'")
        path = providers_dir / "generic.yaml"
    log(f"Using provider: {path.stem}")
    with open(path) as f:
        return yaml.safe_load(f)


def build_saml_url(vpn_url, protocol, provider):
    parsed = urllib.parse.urlparse(
        vpn_url if "://" in vpn_url else f"https://{vpn_url}"
    )
    base = f"{parsed.scheme}://{parsed.netloc}"
    saml_paths = provider.get("saml_paths", {})
    path = saml_paths.get(protocol, saml_paths.get("anyconnect", "/"))
    return f"{base}{path}"


def find_field(page, field_cfg):
    """Find a visible input field using IDs, labels, types, attrs, and scoring."""
    # 1) Try explicit IDs
    for element_id in field_cfg.get("ids", []):
        for frame in page.frames:
            try:
                loc = frame.locator(f"#{element_id}")
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Found field by ID: #{element_id}")
                    return loc.first
            except Exception:
                continue

    # 2) Try explicit attribute selectors
    for attr_sel in field_cfg.get("attrs", []):
        for frame in page.frames:
            try:
                loc = frame.locator(f"input[{attr_sel}]")
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Found field by attr: input[{attr_sel}]")
                    return loc.first
            except Exception:
                continue

    # 3) Try labels
    for label in field_cfg.get("labels", []):
        pattern = re.compile(re.escape(label), re.IGNORECASE)
        for frame in page.frames:
            try:
                loc = frame.get_by_label(pattern)
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Found field by label: {label}")
                    return loc.first
            except Exception:
                continue

    # 4) Fallback: find by input type
    for input_type in field_cfg.get("types", []):
        for frame in page.frames:
            try:
                loc = frame.locator(f"input[type='{input_type}']")
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Found field by type: input[type='{input_type}']")
                    return loc.first
            except Exception:
                continue

    return None


def click_button(page, button_cfg):
    """Click a button using IDs, labels, and CSS selectors."""
    # 1) Try explicit IDs
    for element_id in button_cfg.get("ids", []):
        for frame in page.frames:
            try:
                loc = frame.locator(f"#{element_id}")
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Clicked button by ID: #{element_id}")
                    loc.first.click()
                    return True
            except Exception:
                continue

    # 2) Try labels (buttons and submit inputs)
    for label in button_cfg.get("labels", []):
        pattern = re.compile(re.escape(label), re.IGNORECASE)
        for frame in page.frames:
            for role in ["button", "link"]:
                try:
                    loc = frame.get_by_role(role, name=pattern)
                    if loc.count() > 0 and loc.first.is_visible():
                        debug(f"Clicked {role} by label: {label}")
                        loc.first.click()
                        return True
                except Exception:
                    continue
            try:
                loc = frame.locator("input[type='submit']")
                for idx in range(min(loc.count(), 10)):
                    candidate = loc.nth(idx)
                    value = (candidate.get_attribute("value") or "").strip()
                    if value and pattern.search(value) and candidate.is_visible():
                        debug(f"Clicked submit input by value: {value}")
                        candidate.click()
                        return True
            except Exception:
                continue

    # 3) Try explicit CSS selectors
    for selector in button_cfg.get("selectors", []):
        for frame in page.frames:
            try:
                loc = frame.locator(selector)
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Clicked button by selector: {selector}")
                    loc.first.click()
                    return True
            except Exception:
                continue

    return False


def click_text(page, texts):
    """Click first visible element matching any of the given texts."""
    for text in texts:
        pattern = re.compile(re.escape(text), re.IGNORECASE)
        for frame in page.frames:
            for role in ["button", "link"]:
                try:
                    loc = frame.get_by_role(role, name=pattern)
                    if loc.count() > 0 and loc.first.is_visible():
                        debug(f"Clicked text: {text}")
                        loc.first.click()
                        return True
                except Exception:
                    continue
            try:
                loc = frame.get_by_text(pattern, exact=False)
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Clicked text (fallback): {text}")
                    loc.first.click()
                    return True
            except Exception:
                continue
    return False


def page_has_text(page, texts):
    """Check if any of the given texts appear on the page."""
    for text in texts:
        for frame in page.frames:
            try:
                loc = frame.get_by_text(text, exact=False)
                if loc.count() > 0:
                    return True
            except Exception:
                continue
    return False


def is_vpn_url(url, vpn_host):
    try:
        return urllib.parse.urlparse(url).hostname == vpn_host
    except Exception:
        return False


def cookie_domain_matches(domain, vpn_host):
    domain = domain.lstrip(".")
    return domain == vpn_host or vpn_host.endswith(f".{domain}")


def extract_cookies(context, vpn_host, cookie_names):
    """Extract VPN session cookies from browser context."""
    cookies = context.cookies()
    result = {}
    for cookie in cookies:
        if cookie.get("value") and cookie_domain_matches(
            cookie.get("domain", ""), vpn_host
        ):
            if cookie["name"] in cookie_names:
                result[cookie["name"]] = cookie["value"]
    return result


def run_auth():
    vpn_url = os.environ.get("VPN_URL")
    vpn_user = os.environ.get("VPN_USER")
    vpn_password = os.environ.get("VPN_PASSWORD")
    totp_secret = os.environ.get("VPN_TOTP_SECRET")
    protocol = os.environ.get("VPN_PROTOCOL", "anyconnect")
    provider_name = os.environ.get("VPN_AUTH_PROVIDER", "microsoft")
    custom_config = os.environ.get("VPN_AUTH_CONFIG")
    output_file = os.environ.get("AUTH_OUTPUT_FILE", "/auth/cookie.json")

    if not vpn_url or not vpn_user or not vpn_password:
        log("Error: VPN_URL, VPN_USER, and VPN_PASSWORD are required")
        sys.exit(1)

    provider = load_provider(provider_name, custom_config)
    timeout = int(os.environ.get("AUTH_TIMEOUT", provider.get("timeout", 90)))

    parsed = urllib.parse.urlparse(
        vpn_url if "://" in vpn_url else f"https://{vpn_url}"
    )
    vpn_host = parsed.hostname or vpn_url

    saml_url = build_saml_url(vpn_url, protocol, provider)
    cookie_names = provider.get("cookies", {}).get(
        protocol, provider.get("cookies", {}).get("anyconnect", [])
    )

    log(f"Provider: {provider.get('name', provider_name)}")
    log(f"VPN host: {vpn_host} | Protocol: {protocol}")
    log(f"SAML URL: {saml_url}")
    log(f"Timeout: {timeout}s")

    ignore_tls = os.environ.get("AUTH_IGNORE_TLS_ERRORS", "0") == "1"
    if ignore_tls:
        log("WARNING: TLS certificate validation is DISABLED (AUTH_IGNORE_TLS_ERRORS=1)")
        log("Your credentials will be sent without verifying server certificates.")
        log("Only use this for testing or if you have mounted a custom CA certificate.")

    saml_result = {"saml_response": None, "prelogin_cookie": None}

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
        )
        context = browser.new_context(
            ignore_https_errors=ignore_tls,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        page = context.new_page()

        # Intercept VPN-bound requests for SAMLResponse / prelogin-cookie
        def handle_request(request):
            if not is_vpn_url(request.url, vpn_host):
                return
            if request.post_data:
                try:
                    params = urllib.parse.parse_qs(request.post_data)
                    if "SAMLResponse" in params:
                        saml_result["saml_response"] = params["SAMLResponse"][0]
                        debug(f"Captured SAMLResponse ({len(saml_result['saml_response'])} chars)")
                    if "prelogin-cookie" in params:
                        saml_result["prelogin_cookie"] = params["prelogin-cookie"][0]
                        debug("Captured prelogin-cookie from POST")
                except Exception:
                    pass

        def handle_response(response):
            if not is_vpn_url(response.url, vpn_host):
                return
            try:
                headers = response.headers
                if "prelogin-cookie" in headers:
                    saml_result["prelogin_cookie"] = headers["prelogin-cookie"]
                    debug("Captured prelogin-cookie from response header")
            except Exception:
                pass

        page.on("request", handle_request)
        page.on("response", handle_response)

        # Navigate to SAML URL
        log("Opening SAML portal...")
        for wait_until in ["domcontentloaded", "load", "networkidle"]:
            try:
                page.goto(saml_url, timeout=60000, wait_until=wait_until)
                break
            except Exception as e:
                debug(f"goto with wait_until={wait_until} failed: {e}")
                time.sleep(1)

        if os.environ.get("AUTH_DEBUG") == "1":
            page.screenshot(path="/tmp/saml-step1-portal.png")

        time.sleep(1)

        # Check if already authenticated (cached session)
        if is_vpn_url(page.url, vpn_host):
            vpn_cookies = extract_cookies(context, vpn_host, cookie_names)
            if vpn_cookies or saml_result["saml_response"] or saml_result["prelogin_cookie"]:
                log("Already authenticated (cached session)")
                browser.close()
                return write_result(vpn_cookies, saml_result, vpn_host, protocol, output_file)

        # Main auth loop — handle the non-deterministic login flow
        fields = provider.get("fields", {})
        buttons = provider.get("buttons", {})
        prompts = provider.get("prompts", {})
        filled_username = False
        filled_password = False
        filled_otp = False
        deadline = time.time() + timeout
        step = 0

        while time.time() < deadline:
            if saml_result["saml_response"] or saml_result["prelogin_cookie"]:
                break
            if is_vpn_url(page.url, vpn_host):
                break

            progressed = False
            step += 1

            # Handle "Pick an account" prompt
            pick_cfg = prompts.get("pick_account", {})
            if pick_cfg.get("detect") and page_has_text(page, pick_cfg["detect"]):
                debug("Detected: pick account page")
                if click_text(page, pick_cfg.get("click", [])):
                    progressed = True
                elif click_button(page, buttons.get("next", {})):
                    progressed = True

            # Fill username
            if vpn_user and not filled_username:
                user_field = find_field(page, fields.get("username", {}))
                if user_field:
                    try:
                        user_field.fill(vpn_user)
                        filled_username = True
                        progressed = True
                        log("Filled username")
                        # Only click next if password field is NOT already visible
                        if not find_field(page, fields.get("password", {})):
                            click_button(page, buttons.get("next", {}))
                    except Exception as e:
                        debug(f"Failed to fill username: {e}")

            # Fill password
            if vpn_password and not filled_password:
                pass_field = find_field(page, fields.get("password", {}))
                if pass_field:
                    try:
                        pass_field.fill(vpn_password)
                        filled_password = True
                        progressed = True
                        log("Filled password")
                        click_button(page, buttons.get("sign_in", {}))
                        try:
                            pass_field.press("Enter")
                        except Exception:
                            pass
                    except Exception as e:
                        debug(f"Failed to fill password: {e}")

            # Handle MFA alternative selection (before OTP)
            mfa_alt_cfg = prompts.get("mfa_alternatives", {})
            if mfa_alt_cfg.get("click") and not filled_otp:
                if click_text(page, mfa_alt_cfg.get("click", [])):
                    progressed = True

            # Select TOTP method if needed
            totp_sel_cfg = prompts.get("mfa_totp_select", {})
            if totp_sel_cfg.get("click") and not filled_otp:
                if click_text(page, totp_sel_cfg.get("click", [])):
                    progressed = True
                # Also try direct selector
                sel = totp_sel_cfg.get("selector")
                if sel:
                    for frame in page.frames:
                        try:
                            loc = frame.locator(sel)
                            if loc.count() > 0 and loc.first.is_visible():
                                loc.first.click()
                                progressed = True
                                break
                        except Exception:
                            continue

            # Fill OTP
            if totp_secret and not filled_otp:
                otp_field = find_field(page, fields.get("otp", {}))
                if otp_field:
                    try:
                        otp_field.fill(get_totp_code(totp_secret))
                        filled_otp = True
                        progressed = True
                        log("Filled TOTP code")
                        click_button(page, buttons.get("verify", {}))
                    except Exception as e:
                        debug(f"Failed to fill OTP: {e}")

            # Handle "Stay signed in?" prompt
            stay_cfg = prompts.get("stay_signed_in", {})
            if stay_cfg.get("detect") and page_has_text(page, stay_cfg["detect"]):
                debug("Detected: stay signed in prompt")
                if click_text(page, stay_cfg.get("click", [])):
                    progressed = True
                elif click_button(page, buttons.get("next", {})):
                    progressed = True

            if progressed:
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=5000)
                except Exception:
                    pass
                time.sleep(0.5)
            else:
                time.sleep(1)

            if os.environ.get("AUTH_DEBUG") == "1" and step % 5 == 0:
                page.screenshot(path=f"/tmp/saml-step-{step}.png")

        # Wait a bit for final redirects
        time.sleep(2)

        # Collect cookies
        vpn_cookies = extract_cookies(context, vpn_host, cookie_names)
        browser.close()

    return write_result(vpn_cookies, saml_result, vpn_host, protocol, output_file)


def write_result(vpn_cookies, saml_result, vpn_host, protocol, output_file):
    """Build the cookie string and write result JSON."""
    cookie_parts = []

    if saml_result.get("saml_response"):
        cookie_parts.append(f"SAMLResponse={saml_result['saml_response']}")
    if saml_result.get("prelogin_cookie"):
        cookie_parts.append(f"prelogin-cookie={saml_result['prelogin_cookie']}")
    for name, value in vpn_cookies.items():
        cookie_parts.append(f"{name}={value}")

    if not cookie_parts:
        log("Error: Failed to extract VPN session cookie")
        log("Tips: set AUTH_DEBUG=1 for screenshots, or try VPN_AUTH_PROVIDER=generic")
        sys.exit(1)

    cookie_string = "; ".join(cookie_parts)
    result = {
        "cookie": cookie_string,
        "host": vpn_host,
        "timestamp": int(time.time()),
        "protocol": protocol,
    }

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    log(f"Cookie saved to {output_file}")
    print(cookie_string)


if __name__ == "__main__":
    run_auth()
