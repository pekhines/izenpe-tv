"""Izenpe / TrustedX eIDAS REST API client (user info, identities, remote signing)."""
from __future__ import annotations

import base64
from dataclasses import dataclass

import requests

from . import config
from .config import Environment

# ASN.1 DigestInfo prefixes (RFC 8017) → used to detect/strip DigestInfo wrappers
_DIGESTINFO_PREFIX = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
_RAW_LEN = {20: "sha1", 32: "sha256", 48: "sha384", 64: "sha512"}


@dataclass
class SignIdentity:
    id: str
    labels: list[str]
    raw: dict

    @property
    def is_profesional(self) -> bool:
        return any(l.startswith("CIF:") for l in self.labels)

    @property
    def is_ciudadano(self) -> bool:
        return any(l.lower() == "bakq" for l in self.labels)

    @property
    def cif(self) -> str | None:
        for l in self.labels:
            if l.startswith("CIF:"):
                return l[4:]
        return None


class ApiError(RuntimeError):
    pass


class ApiClient:
    def __init__(self, env: Environment, access_token: str,
                 session: requests.Session | None = None):
        self.env = env
        self.token = access_token
        self.s = session or requests.Session()

    def _headers(self, extra: dict | None = None) -> dict:
        h = {"Authorization": f"Bearer {self.token}"}
        if extra:
            h.update(extra)
        return h

    def _get(self, path: str) -> dict:
        r = self.s.get(f"{self.env.base_url}{path}", headers=self._headers(), timeout=30)
        if r.status_code != 200:
            raise ApiError(f"GET {path} → HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def user_info(self) -> dict:
        return self._get(config.PATH_USERINFO)

    def list_identities(self) -> list[SignIdentity]:
        data = self._get(config.PATH_SIGN_IDENTITIES)
        items = data.get("items") or data.get("sign_identities") or data if isinstance(data, list) else data.get("items", [])
        if isinstance(data, dict) and not items:
            # TrustedX typically wraps in {"items":[...]}; fall back to any list value
            for v in data.values():
                if isinstance(v, list):
                    items = v
                    break
        out = []
        for it in items or []:
            out.append(SignIdentity(id=it.get("id") or it.get("sign_identity_id"),
                                    labels=it.get("labels", []), raw=it))
        return out

    def identity_detail(self, identity_id: str) -> dict:
        return self._get(config.PATH_SIGN_IDENTITIES + identity_id)

    def certificate_der(self, identity_id: str) -> bytes:
        """Return the identity's X.509 certificate as DER bytes."""
        d = self.identity_detail(identity_id)
        ident = d.get("identity", {}) if isinstance(d.get("identity"), dict) else {}
        # real shape: {"identity": {..., "details": {"certificate": b64, "public_key": ...}}}
        b64 = (ident.get("details", {}).get("certificate")
               or ident.get("certificate")
               or d.get("certificate") or d.get("certificate_b64"))
        if not b64:
            raise ApiError(f"no certificate in identity detail: keys={list(d)}")
        return base64.b64decode(b64)

    def sign_raw(self, identity_id: str, digest: bytes, *, algorithm: str = "rsa-sha256",
                 pss: bool = False) -> bytes:
        """Remote-sign a hash. `digest` may be a raw hash or a full DigestInfo.

        Returns the raw signature bytes.
        """
        alg = algorithm
        body: dict = {"sign_identity_id": identity_id}

        # Decide whether we are sending a raw hash (digest_value) or DigestInfo (data).
        hash_alg = _RAW_LEN.get(len(digest))
        if hash_alg:
            # raw hash (PKCS#1 v1.5 or PSS): the bridge always uses digest_value
            body["digest_value"] = base64.b64encode(digest).decode()
            alg = f"rsa-{hash_alg}"
        else:
            # Treat as DigestInfo / already-wrapped; send in `data`.
            body["data"] = base64.b64encode(digest).decode()
        if pss and not alg.startswith("rsa-pss"):
            suffix = alg.split("-", 1)[1] if "-" in alg else "sha256"
            alg = f"rsa-pss-mgf1-{suffix}"
        body["signature_algorithm"] = alg

        r = self.s.post(f"{self.env.base_url}{config.PATH_SIGN_RAW}", json=body,
                        headers=self._headers({"Content-Type": "application/json"}), timeout=60)
        if r.status_code not in (200, 201):
            raise ApiError(f"sign → HTTP {r.status_code}: {r.text[:300]}")
        # Izenpe returns the raw signature bytes (application/octet-stream).
        ctype = (r.headers.get("Content-Type") or "").lower()
        if "json" not in ctype:
            return r.content
        return _decode_signature(r.json())


def _decode_signature(j) -> bytes:
    """Signature can come back as base64 string or {'bytes':[...]} or {'signature':...}."""
    if isinstance(j, str):
        return base64.b64decode(j)
    if isinstance(j, dict):
        for k in ("signature", "value", "data", "signature_value"):
            v = j.get(k)
            if isinstance(v, str):
                return base64.b64decode(v)
            if isinstance(v, dict) and "bytes" in v:
                return bytes(v["bytes"])
        if "bytes" in j:
            return bytes(j["bytes"])
    raise ApiError(f"cannot decode signature response: {str(j)[:200]}")
