#!/usr/bin/env python3
"""Complete a Keycloak OAuth 2.0 Device Authorization Grant consent step
programmatically. Used by scripts/run_integration_keycloak.sh's device-code
test (S-17).

Inputs (via argv):
  1. verification_uri_complete -- e.g. http://localhost:8080/realms/quack-test/device?user_code=ABCD-EFGH
  2. username                  -- 'alice'
  3. password                  -- 'secret'

Exit code:
  0 -- consent submitted successfully
  1 -- failed (HTML scraping or HTTP error; details to stderr)

Uses urllib + html.parser from the standard library so the integration
runner has no extra Python dependencies.
"""

import html.parser
import sys
import urllib.parse
import urllib.request


class FormActionExtractor(html.parser.HTMLParser):
    """Extracts the `action` attribute of the first <form> tag in the page."""
    def __init__(self):
        super().__init__()
        self.action = None

    def handle_starttag(self, tag, attrs):
        if self.action is not None or tag != "form":
            return
        for name, value in attrs:
            if name == "action" and value:
                self.action = value
                return


def fetch_and_extract_form(opener, url):
    with opener.open(url) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        final_url = resp.geturl()
    parser = FormActionExtractor()
    parser.feed(body)
    if parser.action is None:
        sys.stderr.write(f"FAIL: no <form action=...> in {final_url}\n")
        sys.stderr.write("Body excerpt:\n" + body[:600] + "\n")
        sys.exit(1)
    # Form action may be relative; resolve against the page URL.
    return urllib.parse.urljoin(final_url, parser.action)


def main(argv):
    if len(argv) != 4:
        sys.stderr.write(f"usage: {argv[0]} <verification_uri_complete> <username> <password>\n")
        return 2

    verification_uri, username, password = argv[1], argv[2], argv[3]

    cookie_jar = urllib.request.HTTPCookieProcessor()
    opener = urllib.request.build_opener(cookie_jar)

    # 1. GET the verification URL. Keycloak shows the login form.
    sys.stderr.write(f"[consent] GET {verification_uri}\n")
    login_action = fetch_and_extract_form(opener, verification_uri)

    # 2. POST credentials. With consentRequired=false on the client this
    # implicitly approves the device.
    sys.stderr.write(f"[consent] POST {login_action} (login as {username})\n")
    form = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "credentialId": "",
    }).encode("ascii")
    req = urllib.request.Request(login_action, data=form)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with opener.open(req) as resp:
        final_url = resp.geturl()
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")

    sys.stderr.write(f"[consent] response status={status} url={final_url}\n")

    # Keycloak with consentRequired=false redirects to a "Device login success"
    # page after a successful POST. The body contains kc-feedback-success or
    # similar markers. If it failed (wrong creds, code expired), the page
    # contains an error message.
    low = body.lower()
    if "invalid" in low or "incorrect" in low or "error" in low and "success" not in low:
        # Heuristic: if the body talks about an error and not a success,
        # treat as failure. Keycloak's exact wording varies by version.
        if "kc-feedback-success" not in body and "device_grant.success" not in body and "successfully granted" not in low:
            sys.stderr.write("FAIL: login/consent appears to have failed\n")
            sys.stderr.write("Body excerpt:\n" + body[:600] + "\n")
            return 1

    # Some Keycloak versions show a separate "Grant access" consent page.
    # With consentRequired=false this should not appear, but handle it
    # defensively: if we see another form, submit it too.
    parser2 = FormActionExtractor()
    parser2.feed(body)
    if parser2.action is not None and "device" in parser2.action.lower():
        consent_action = urllib.parse.urljoin(final_url, parser2.action)
        sys.stderr.write(f"[consent] POST {consent_action} (approve)\n")
        form2 = urllib.parse.urlencode({"accept": "Yes"}).encode("ascii")
        req2 = urllib.request.Request(consent_action, data=form2)
        req2.add_header("Content-Type", "application/x-www-form-urlencoded")
        with opener.open(req2) as resp2:
            sys.stderr.write(f"[consent] consent response status={resp2.status}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
