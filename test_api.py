"""
NexoraGuard — Groq API Connection Diagnostic
Run from the project root:

    python test_api.py                    # reads key from Settings (user_config.json)
    python test_api.py --key gsk_abc123   # test a specific key directly

This script checks every layer of the connection and tells you exactly what is wrong.
"""

import sys
import os
import argparse
import socket
import ssl

# ── Resolve key ───────────────────────────────────────────────────────────────

def _get_key_from_settings() -> str:
    """Try to read the encrypted key from user_config.json (same logic as the EXE)."""
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
        from user_config import get_api_key
        return get_api_key()
    except Exception as e:
        return ""


def _resolve_key(cli_key: str) -> str:
    if cli_key:
        return cli_key.strip()
    key = _get_key_from_settings()
    if key:
        print(f"  [Settings] Found stored key: {key[:8]}...{key[-4:]}")
        return key
    # Fall back to .env
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
    except Exception:
        pass
    env_key = os.getenv("GROQ_API_KEY", "")
    if env_key:
        print(f"  [.env] Found GROQ_API_KEY: {env_key[:8]}...{env_key[-4:]}")
        return env_key
    return ""


# ── Individual checks ─────────────────────────────────────────────────────────

GROQ_HOST = "api.groq.com"
GROQ_PORT = 443
GROQ_URL  = "https://api.groq.com/openai/v1/chat/completions"


def check_dns() -> bool:
    print("\n[1] DNS Resolution")
    try:
        ip = socket.gethostbyname(GROQ_HOST)
        print(f"    OK — {GROQ_HOST} -> {ip}")
        return True
    except socket.gaierror as e:
        print(f"    FAIL — Cannot resolve '{GROQ_HOST}': {e}")
        print("    Likely cause: No internet connection, or DNS blocked")
        return False


def check_tcp() -> bool:
    print("\n[2] TCP Connection (port 443)")
    try:
        s = socket.create_connection((GROQ_HOST, GROQ_PORT), timeout=5)
        s.close()
        print(f"    OK — TCP connected to {GROQ_HOST}:{GROQ_PORT}")
        return True
    except OSError as e:
        print(f"    FAIL — {e}")
        print("    Likely cause: Firewall or antivirus blocking outbound HTTPS (port 443)")
        return False


def check_ssl() -> bool:
    print("\n[3] SSL / TLS Handshake")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((GROQ_HOST, GROQ_PORT), timeout=5),
            server_hostname=GROQ_HOST
        ) as ssock:
            print(f"    OK — TLS {ssock.version()}, cipher: {ssock.cipher()[0]}")
        return True
    except ssl.SSLCertVerificationError as e:
        print(f"    FAIL (SSL Certificate Error) — {e}")
        print("    Likely cause: Antivirus / corporate proxy doing SSL inspection")
        return False
    except Exception as e:
        print(f"    FAIL — {e}")
        return False


def check_http_reachability() -> bool:
    print("\n[4] HTTP Reachability (GET /openai/v1/models)")
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": "Bearer test-key-reachability-check"}
        )
        try:
            urllib.request.urlopen(req, timeout=8)
        except urllib.error.HTTPError as e:
            # Any HTTP response (even 401) means the server is reachable
            print(f"    OK — Server reachable, HTTP {e.code} returned")
            return True
        return True
    except urllib.error.URLError as e:
        print(f"    FAIL — {e.reason}")
        return False
    except Exception as e:
        print(f"    FAIL — {e}")
        return False


def check_api_key(api_key: str) -> bool:
    print("\n[5] API Key Validation")

    if not api_key:
        print("    SKIP — No API key provided")
        print("    To test a key: python test_api.py --key gsk_your_key_here")
        return False

    key_preview = f"{api_key[:8]}...{api_key[-4:] if len(api_key) > 12 else ''}"
    print(f"    Key: {key_preview}")
    print(f"    Length: {len(api_key)} chars", end="")

    # Groq keys start with "gsk_"
    if not api_key.startswith("gsk_"):
        print()
        print("    WARNING: Groq API keys typically start with 'gsk_'")
        print("             If this is an OpenAI key (sk-...) it will NOT work with Groq")

    # Check for common pasting errors
    if " " in api_key:
        print()
        print("    ERROR: Key contains spaces — copy-paste error. Remove all spaces.")
        return False
    if "\n" in api_key or "\r" in api_key:
        print()
        print("    ERROR: Key contains newline characters — copy-paste error.")
        return False
    print()

    # Make the actual API call
    print("\n[6] Live API Test (sending 'Hello' to llama-3.3-70b-versatile)")
    try:
        import groq as groq_module
    except ImportError:
        print("    FAIL — groq package not installed: pip install groq")
        return False

    try:
        client = groq_module.Groq(api_key=api_key)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
            max_tokens=10,
            temperature=0
        )
        answer = resp.choices[0].message.content.strip()
        print(f"    OK — Model responded: '{answer}'")
        print(f"    Tokens used: prompt={resp.usage.prompt_tokens}, "
              f"completion={resp.usage.completion_tokens}")
        print("\n    [RESULT] API key is VALID and working correctly.")
        return True

    except groq_module.AuthenticationError as e:
        print(f"    FAIL [401 Unauthorized] — API key is invalid or expired")
        print(f"    Detail : {e}")
        print("\n    Fix:")
        print("      1. Go to https://console.groq.com/keys")
        print("      2. Create a new API key")
        print("      3. Open NexoraGuard → Settings → remove old key → paste new key")
        return False

    except groq_module.RateLimitError as e:
        print(f"    INFO [429 Rate Limit] — Key is valid, but quota is exhausted")
        print(f"    Detail : {e}")
        print("\n    Fix: Free tier resets at midnight UTC. Wait or upgrade at console.groq.com")
        return False

    except groq_module.BadRequestError as e:
        print(f"    FAIL [400 Bad Request] — {e}")
        return False

    except groq_module.APIStatusError as e:
        print(f"    FAIL [HTTP {e.status_code}] — {e.message}")
        print(f"    Full response: {e.response}")
        return False

    except groq_module.APIConnectionError as e:
        print(f"    FAIL [Connection Error] — {e}")
        print("    The key may be valid, but the network check above should have caught this.")
        return False

    except Exception as e:
        print(f"    FAIL [Unexpected Error] — {type(e).__name__}: {e}")
        return False


# ── Header verification ───────────────────────────────────────────────────────

def show_request_headers(api_key: str):
    print("\n[7] Authorization Header Check")
    if not api_key:
        print("    SKIP — No key to verify")
        return
    header_value = f"Bearer {api_key}"
    print(f"    Header sent   : Authorization: Bearer {api_key[:8]}...{api_key[-4:]}")
    print(f"    Full length   : {len(header_value)} chars")
    print(f"    Base URL      : https://api.groq.com/openai/v1")
    print(f"    Model         : llama-3.3-70b-versatile")
    if not api_key.startswith("gsk_"):
        print("    WARNING: Key does not start with 'gsk_' — verify you are using a Groq key")
    else:
        print("    Key prefix    : gsk_ (correct for Groq)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NexoraGuard API Connection Diagnostic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--key", "-k", metavar="API_KEY",
                        help="Groq API key to test (skips stored key lookup)")
    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  NexoraGuard — API Connection Diagnostic")
    print("  Provider  : Groq  (https://api.groq.com)")
    print("=" * 60)

    api_key = _resolve_key(args.key)

    dns_ok  = check_dns()
    tcp_ok  = check_tcp()         if dns_ok  else False
    ssl_ok  = check_ssl()         if tcp_ok  else False
    http_ok = check_http_reachability() if ssl_ok else False
    key_ok  = check_api_key(api_key)    if http_ok else False

    if api_key or http_ok:
        show_request_headers(api_key)

    print()
    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  DNS         : {'PASS' if dns_ok  else 'FAIL'}")
    print(f"  TCP         : {'PASS' if tcp_ok  else 'FAIL'}")
    print(f"  SSL         : {'PASS' if ssl_ok  else 'FAIL'}")
    print(f"  HTTP reach  : {'PASS' if http_ok else 'FAIL'}")
    print(f"  API key     : {'PASS' if key_ok  else ('SKIP (no key)' if not api_key else 'FAIL')}")

    if not dns_ok:
        print("\n  Root cause: No internet / DNS blocked")
    elif not tcp_ok:
        print("\n  Root cause: Firewall blocking port 443 outbound")
    elif not ssl_ok:
        print("\n  Root cause: SSL interception (antivirus / proxy)")
    elif not http_ok:
        print("\n  Root cause: Groq server unreachable (check status.groq.com)")
    elif not api_key:
        print("\n  Next step: python test_api.py --key gsk_your_key_here")
    elif key_ok:
        print("\n  Everything is working correctly.")
    print()


if __name__ == "__main__":
    main()
