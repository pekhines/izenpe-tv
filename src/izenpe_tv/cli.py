"""Command-line interface for the Izenpe Tarjeta Virtual Linux client.

Milestone 1: validate the protocol end-to-end (login, whoami, identities, cert, sign).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys

from . import api, config, login, storage


def _env(args) -> config.Environment:
    return config.ENVIRONMENTS[args.env]


def cmd_login(args):
    env = _env(args)
    if args.manual:
        login.login_manual(env, ui_locales=args.locale, login_hint=args.dni,
                           open_browser=not args.no_browser)
    else:
        try:
            login.login_auto(env, ui_locales=args.locale, login_hint=args.dni)
        except login.oauth.OAuthError as e:
            print(f"\nAutomatic capture failed: {e}\nFalling back to manual paste.\n")
            login.login_manual(env, ui_locales=args.locale, login_hint=args.dni,
                               open_browser=not args.no_browser)


def cmd_install_handler(args):
    path = login.install_scheme_handler()
    print(f"Registered oauth-swift:// handler: {path}")


def cmd_logout(args):
    storage.clear_token(_env(args).profile)
    print("Token cleared.")


def _client(args) -> api.ApiClient:
    env = _env(args)
    tok = login.ensure_token(env)
    return api.ApiClient(env, tok.access_token)


def cmd_whoami(args):
    info = _client(args).user_info()
    import json
    print(json.dumps(info, indent=2, ensure_ascii=False))


def cmd_identities(args):
    c = _client(args)
    ids = c.list_identities()
    if not ids:
        print("No sign identities found.")
        return
    for i in ids:
        kind = "profesional" if i.is_profesional else "ciudadano" if i.is_ciudadano else "?"
        print(f"- {i.id}  [{kind}]  labels={i.labels}")


def cmd_cert(args):
    der = _client(args).certificate_der(args.identity)
    if args.pem:
        b64 = base64.encodebytes(der).decode()
        out = "-----BEGIN CERTIFICATE-----\n" + b64 + "-----END CERTIFICATE-----\n"
        sys.stdout.write(out)
    elif args.out:
        with open(args.out, "wb") as f:
            f.write(der)
        print(f"Wrote {len(der)} bytes (DER) to {args.out}")
    else:
        _print_cert_summary(der)


def _print_cert_summary(der: bytes):
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        print("Subject :", c.subject.rfc4514_string())
        print("Issuer  :", c.issuer.rfc4514_string())
        print("Serial  :", hex(c.serial_number))
        print("From    :", c.not_valid_before_utc)
        print("Until   :", c.not_valid_after_utc)
    except Exception as e:
        print(f"(cryptography not available or parse error: {e})")
        print(f"DER length: {len(der)} bytes")


def cmd_sign(args):
    c = _client(args)
    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    elif args.data is not None:
        data = args.data.encode()
    else:
        data = sys.stdin.buffer.read()
    digest = hashlib.new(args.hash, data).digest()
    sig = c.sign_raw(args.identity, digest, algorithm=f"rsa-{args.hash}", pss=args.pss)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(sig)
        print(f"Wrote {len(sig)}-byte signature to {args.out}")
    else:
        print(base64.b64encode(sig).decode())


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="izenpe-tv",
                                description="Unofficial Linux client for Izenpe Tarjeta Virtual")
    p.add_argument("--env", choices=list(config.ENVIRONMENTS), default="profesional",
                   help="environment/profile (default: profesional)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("login", help="log in via the system browser")
    sp.add_argument("--locale", default="eu", choices=["eu", "es"])
    sp.add_argument("--dni", help="prefill DNI/NIE (login_hint)")
    sp.add_argument("--manual", action="store_true",
                    help="paste the redirect URL instead of auto-capturing it")
    sp.add_argument("--no-browser", action="store_true", help="don't auto-open the browser")
    sp.set_defaults(func=cmd_login)

    sp = sub.add_parser("install-handler", help="register the oauth-swift:// browser handler")
    sp.set_defaults(func=cmd_install_handler)

    sp = sub.add_parser("logout", help="clear stored token")
    sp.set_defaults(func=cmd_logout)

    sp = sub.add_parser("whoami", help="show user info")
    sp.set_defaults(func=cmd_whoami)

    sp = sub.add_parser("identities", help="list signing identities")
    sp.set_defaults(func=cmd_identities)

    sp = sub.add_parser("cert", help="fetch an identity's certificate")
    sp.add_argument("identity", help="sign_identity_id")
    sp.add_argument("--pem", action="store_true", help="print PEM to stdout")
    sp.add_argument("--out", help="write DER to file")
    sp.set_defaults(func=cmd_cert)

    sp = sub.add_parser("sign", help="remote-sign data (hashes locally, signs in the HSM)")
    sp.add_argument("identity", help="sign_identity_id")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--file", help="file to sign (default: stdin)")
    g.add_argument("--data", help="literal string to sign")
    sp.add_argument("--hash", default="sha256", choices=["sha1", "sha256", "sha384", "sha512"])
    sp.add_argument("--pss", action="store_true", help="use RSA-PSS instead of PKCS#1 v1.5")
    sp.add_argument("--out", help="write raw signature to file")
    sp.set_defaults(func=cmd_sign)

    return p


CRED_HELP = """\
OAuth client credentials are not configured. They are embedded in the official Izenpe
desktop app; extract them and provide them via either:
  * env: IZENPE_TV_CLIENT_IDS=id1,id2 IZENPE_TV_CLIENT_SECRET_PROD=... [IZENPE_TV_CLIENT_SECRET_DESA=...]
  * file: ~/.config/izenpe-tv/client.toml  (see client.toml.example)
See docs/PROTOCOL.md §2.
"""


def main(argv=None):
    args = build_parser().parse_args(argv)
    config.load_client_credentials()
    if not config.credentials_present():
        print(CRED_HELP, file=sys.stderr)
        sys.exit(2)
    try:
        args.func(args)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
