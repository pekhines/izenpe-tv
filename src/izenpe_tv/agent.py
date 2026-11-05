"""izenpe-tv-agent: a local Unix-socket daemon the PKCS#11 module talks to.

The PKCS#11 .so is deliberately thin: it forwards object enumeration and signing to this
agent, which holds the OAuth session and performs the remote signature against Izenpe.

Wire protocol (AF_UNIX stream): each message is a 4-byte big-endian length prefix
followed by a UTF-8 JSON object.

Requests:
  {"op":"ping"}
  {"op":"list_objects"}
  {"op":"sign","id":<hex>,"mechanism":<str>,"hash":<str|null>,"data_b64":<str>}

Responses:
  {"ok":true, ...}  |  {"ok":false,"error":<str>}

A "mock" backend (self-signed cert + local RSA key, no network) lets the whole PKCS#11
path be tested offline.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import threading

from . import api, config, login

SOCKET_ENV = "IZENPE_TV_SOCK"


def default_socket_path() -> str:
    """$XDG_RUNTIME_DIR/izenpe-tv/agent.sock — a directory, so sandboxes (flatpak
    Firefox: --filesystem=xdg-run/izenpe-tv) keep seeing it when the agent restarts."""
    if os.environ.get(SOCKET_ENV):
        return os.environ[SOCKET_ENV]
    run = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    if not os.path.isdir(run):
        run = os.path.expanduser("~/.cache")
    d = os.path.join(run, "izenpe-tv")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return os.path.join(d, "agent.sock")


# ---------------------------------------------------------------- object model

def _cert_to_object(cert_der: bytes, label: str, key_id: bytes) -> dict:
    """Build the attribute bundle the PKCS#11 module needs for one identity."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa

    cert = x509.load_der_x509_certificate(cert_der)
    pub = cert.public_key()
    obj = {
        "id": key_id.hex(),
        "label": label,
        "cert_der_b64": base64.b64encode(cert_der).decode(),
        "subject_der_b64": base64.b64encode(cert.subject.public_bytes()).decode(),
        "issuer_der_b64": base64.b64encode(cert.issuer.public_bytes()).decode(),
        "serial_b64": base64.b64encode(
            cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8 or 1, "big")
        ).decode(),
    }
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
        e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
        obj["key_type"] = "RSA"
        obj["modulus_b64"] = base64.b64encode(n).decode()
        obj["public_exponent_b64"] = base64.b64encode(e).decode()
        obj["modulus_bits"] = nums.n.bit_length()
    return obj


# ---------------------------------------------------------------- backends

class Backend:
    def list_objects(self) -> list[dict]:
        raise NotImplementedError

    def sign(self, key_id: str, mechanism: str, hash_hint: str | None, data: bytes) -> bytes:
        raise NotImplementedError


class IzenpeBackend(Backend):
    """Real backend: talks to Izenpe via the REST API using the stored OAuth token."""

    def __init__(self, env_name: str):
        config.load_client_credentials()
        self.env = config.ENVIRONMENTS[env_name]
        self._objs: dict[str, dict] = {}       # key_id hex -> object bundle
        self._ident: dict[str, str] = {}        # key_id hex -> sign_identity_id

    def _client(self) -> api.ApiClient:
        tok = login.ensure_token(self.env)
        return api.ApiClient(self.env, tok.access_token)

    def list_objects(self) -> list[dict]:
        c = self._client()
        info = c.user_info()
        my_cif = _extract_cif(info)
        out = []
        self._objs.clear()
        self._ident.clear()
        for ident in c.list_identities():
            if self.env.profile == "profesional":
                if not ident.is_profesional:
                    continue
                if my_cif and ident.cif and ident.cif != my_cif:
                    continue
            elif self.env.profile == "ciudadano" and not ident.is_ciudadano:
                continue
            try:
                der = c.certificate_der(ident.id)
            except Exception:
                continue
            key_id = hashlib.sha1(der).digest()  # stable CKA_ID
            obj = _cert_to_object(der, ident.id, key_id)
            self._objs[obj["id"]] = obj
            self._ident[obj["id"]] = ident.id
            out.append(obj)
        return out

    def sign(self, key_id: str, mechanism: str, hash_hint: str | None, data: bytes) -> bytes:
        if key_id not in self._ident:
            self.list_objects()
        identity_id = self._ident.get(key_id)
        if identity_id is None:
            raise KeyError(f"unknown key id {key_id}")
        digest, alg, pss = _prepare_digest(mechanism, hash_hint, data)
        return self._client().sign_raw(identity_id, digest, algorithm=alg, pss=pss)


class MockBackend(Backend):
    """Offline backend: one self-signed RSA cert signed with a local key. For tests."""

    def __init__(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "IZENPE MOCK - 00000000T"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Izenpe TV Linux (mock)"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(self._key, hashes.SHA256())
        )
        self._der = cert.public_bytes(serialization.Encoding.DER)
        self._id = hashlib.sha1(self._der).digest()
        self._serialization = serialization

    def list_objects(self) -> list[dict]:
        return [_cert_to_object(self._der, "mock-identity", self._id)]

    def sign(self, key_id: str, mechanism: str, hash_hint: str | None, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils
        digest, alg, pss = _prepare_digest(mechanism, hash_hint, data)
        hash_name = alg.split("-")[-1]
        halg = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(),
                "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[hash_name]
        pad = (padding.PSS(mgf=padding.MGF1(halg), salt_length=padding.PSS.DIGEST_LENGTH)
               if pss else padding.PKCS1v15())
        # `digest` here is a raw hash (we always produce raw for mock)
        return self._key.sign(digest, pad, utils.Prehashed(halg))


# ---------------------------------------------------------------- mechanism map

_HASH_OF_MECH = {
    "CKM_SHA1_RSA_PKCS": "sha1", "CKM_SHA256_RSA_PKCS": "sha256",
    "CKM_SHA384_RSA_PKCS": "sha384", "CKM_SHA512_RSA_PKCS": "sha512",
    "CKM_SHA1_RSA_PKCS_PSS": "sha1", "CKM_SHA256_RSA_PKCS_PSS": "sha256",
    "CKM_SHA384_RSA_PKCS_PSS": "sha384", "CKM_SHA512_RSA_PKCS_PSS": "sha512",
}
_RAW_LEN = {20: "sha1", 32: "sha256", 48: "sha384", 64: "sha512"}
_HASH_OIDS = {  # DER-encoded OID contents → hash name
    bytes.fromhex("2b0e03021a"): "sha1",
    bytes.fromhex("608648016503040201"): "sha256",
    bytes.fromhex("608648016503040202"): "sha384",
    bytes.fromhex("608648016503040203"): "sha512",
}


def _parse_digestinfo(data: bytes) -> tuple[str, bytes] | None:
    """Parse a PKCS#1 DigestInfo; return (hash_name, raw_hash) or None.

    Accepts AlgorithmIdentifier parameters both as NULL (RFC 8017) and absent:
    Idazki Desktop sends the latter (49-byte SHA-256 DigestInfo).
    All lengths involved are < 128, so only DER short-form lengths are handled.
    """
    try:
        if data[0] != 0x30 or data[1] != len(data) - 2:
            return None
        if data[2] != 0x30:
            return None
        alg_len = data[3]
        alg = data[4:4 + alg_len]
        p = 4 + alg_len
        if alg[0] != 0x06:
            return None
        oid = alg[2:2 + alg[1]]
        if alg[2 + alg[1]:] not in (b"", b"\x05\x00"):
            return None
        h = _HASH_OIDS.get(oid)
        if h is None or data[p] != 0x04:
            return None
        dlen = data[p + 1]
        digest = data[p + 2:p + 2 + dlen]
        if dlen != _raw_len_for(h) or p + 2 + dlen != len(data):
            return None
        return h, digest
    except IndexError:
        return None


def _prepare_digest(mechanism: str, hash_hint: str | None, data: bytes):
    """Return (digest_bytes_raw_hash, rsa-alg, pss?) ready for api.sign_raw (raw path)."""
    pss = mechanism.endswith("_PSS") or mechanism == "CKM_RSA_PKCS_PSS"
    if mechanism in _HASH_OF_MECH:
        # combined hash+sign: we have the full message; hash it ourselves
        h = _HASH_OF_MECH[mechanism]
        digest = hashlib.new(h, data).digest()
        return digest, f"rsa-{h}", pss
    if mechanism in ("CKM_RSA_PKCS", "CKM_RSA_PKCS_PSS"):
        di = _parse_digestinfo(data) if mechanism == "CKM_RSA_PKCS" else None
        if di:
            # strip DigestInfo ASN.1 wrapper → raw hash
            h, digest = di
            return digest, f"rsa-{h}", False
        if len(data) in _RAW_LEN:
            return data, f"rsa-{_RAW_LEN[len(data)]}", pss
        h = hash_hint or "sha256"
        return data, f"rsa-{h}", pss
    raise ValueError(f"unsupported mechanism {mechanism}")


def _raw_len_for(h: str) -> int:
    return {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}[h]


# ---------------------------------------------------------------- server

def _recv_msg(conn) -> dict | None:
    hdr = _recvn(conn, 4)
    if not hdr:
        return None
    (n,) = struct.unpack(">I", hdr)
    body = _recvn(conn, n)
    return json.loads(body.decode())


def _recvn(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _send_msg(conn, obj: dict):
    body = json.dumps(obj).encode()
    conn.sendall(struct.pack(">I", len(body)) + body)


BINARY_MAGIC = b"IZTV"
# binary op codes
OP_PING, OP_LIST, OP_SIGN = 1, 2, 3


def _w_bytes(parts: list, b: bytes):
    parts.append(struct.pack(">I", len(b)))
    parts.append(b)


def _handle_binary(conn, backend: Backend):
    """Length-free binary protocol used by the C PKCS#11 module.

    Client already sent the 4-byte magic. Each request: op(u8) + op-specific fields,
    where every variable field is u32 length + bytes.
    """
    def readn(n):
        return _recvn(conn, n)

    def read_field():
        h = readn(4)
        if h is None:
            return None
        (ln,) = struct.unpack(">I", h)
        return readn(ln) if ln else b""

    while True:
        opb = readn(1)
        if not opb:
            return
        op = opb[0]
        try:
            if op == OP_PING:
                conn.sendall(b"\x00")
            elif op == OP_LIST:
                objs = backend.list_objects()
                parts = [b"\x00", struct.pack(">I", len(objs))]
                for o in objs:
                    _w_bytes(parts, bytes.fromhex(o["id"]))
                    _w_bytes(parts, o.get("label", "").encode())
                    _w_bytes(parts, base64.b64decode(o["cert_der_b64"]))
                    _w_bytes(parts, base64.b64decode(o.get("modulus_b64", "")))
                    _w_bytes(parts, base64.b64decode(o.get("public_exponent_b64", "")))
                    _w_bytes(parts, base64.b64decode(o["subject_der_b64"]))
                    _w_bytes(parts, base64.b64decode(o["issuer_der_b64"]))
                    _w_bytes(parts, base64.b64decode(o["serial_b64"]))
                    parts.append(struct.pack(">I", int(o.get("modulus_bits", 0))))
                conn.sendall(b"".join(parts))
            elif op == OP_SIGN:
                key_id = read_field().decode()
                mech = read_field().decode()
                hb = read_field()
                hash_hint = hb.decode() if hb else None
                data = read_field()
                sig = backend.sign(key_id, mech, hash_hint, data)
                conn.sendall(b"\x00" + struct.pack(">I", len(sig)) + sig)
            else:
                conn.sendall(b"\x01")
        except Exception as e:  # noqa: BLE001
            print(f"izenpe-tv-agent: op {op} failed: {type(e).__name__}: {e}", flush=True)
            msg = f"{type(e).__name__}: {e}".encode()
            try:
                conn.sendall(b"\x01" + struct.pack(">I", len(msg)) + msg)
            except OSError:
                pass


def _handle(conn, backend: Backend):
    try:
        first = _recvn(conn, 4)
        if first is None:
            return
        if first == BINARY_MAGIC:
            _handle_binary(conn, backend)
            return
        # JSON mode: `first` is the 4-byte length prefix of the first message
        (n,) = struct.unpack(">I", first)
        body = _recvn(conn, n)
        req0 = json.loads(body.decode()) if body else None
        _handle_json_loop(conn, backend, req0)
    finally:
        conn.close()


def _handle_json_loop(conn, backend: Backend, req0):
    req = req0
    while req is not None:
        op = req.get("op")
        try:
            if op == "ping":
                _send_msg(conn, {"ok": True})
            elif op == "list_objects":
                _send_msg(conn, {"ok": True, "objects": backend.list_objects()})
            elif op == "sign":
                data = base64.b64decode(req["data_b64"])
                sig = backend.sign(req["id"], req["mechanism"], req.get("hash"), data)
                _send_msg(conn, {"ok": True, "signature_b64": base64.b64encode(sig).decode()})
            else:
                _send_msg(conn, {"ok": False, "error": f"unknown op {op!r}"})
        except Exception as e:  # noqa: BLE001
            _send_msg(conn, {"ok": False, "error": f"{type(e).__name__}: {e}"})
        req = _recv_msg(conn)


def serve(backend: Backend, sock_path: str | None = None):
    sock_path = sock_path or default_socket_path()
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv.listen(8)
    print(f"izenpe-tv-agent listening on {sock_path}")
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=_handle, args=(conn, backend), daemon=True).start()
    finally:
        srv.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)


def _extract_cif(info: dict) -> str | None:
    for k in ("cif", "CIF"):
        if info.get(k):
            return info[k]
    org = info.get("organization")
    if isinstance(org, dict):
        return org.get("cif") or org.get("id")
    for label in info.get("labels", []):
        if isinstance(label, str) and label.startswith("CIF:"):
            return label[4:]
    return None


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="izenpe-tv-agent")
    p.add_argument("--env", default="profesional", choices=list(config.ENVIRONMENTS))
    p.add_argument("--mock", action="store_true", help="offline self-signed backend (testing)")
    p.add_argument("--socket", help="unix socket path")
    args = p.parse_args(argv)
    backend: Backend = MockBackend() if args.mock else IzenpeBackend(args.env)
    serve(backend, args.socket)


if __name__ == "__main__":
    main()
