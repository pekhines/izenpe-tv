"""End-to-end smoke test for the compiled PKCS#11 module against the mock agent.

Skips cleanly if the module isn't built yet. Run:
    make -C pkcs11            # build libizenpe-pkcs11.so
    python tests/test_pkcs11_module.py
"""
from __future__ import annotations

import ctypes as C
import os
import subprocess
import sys
import time
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SO = os.path.join(ROOT, "pkcs11", "libizenpe-pkcs11.so")

CKA_CLASS, CKA_VALUE, CKA_ID = 0, 0x11, 0x102
CKO_CERTIFICATE, CKO_PRIVATE_KEY = 1, 3
CKM_SHA256_RSA_PKCS = 0x40
CKF_SERIAL_SESSION = 4
CK_ULONG = C.c_ulong


class CK_ATTRIBUTE(C.Structure):
    _fields_ = [("type", CK_ULONG), ("pValue", C.c_void_p), ("ulValueLen", CK_ULONG)]


class CK_MECHANISM(C.Structure):
    _fields_ = [("mechanism", CK_ULONG), ("pParameter", C.c_void_p), ("ulParameterLen", CK_ULONG)]


def main() -> int:
    if not os.path.exists(SO):
        print(f"SKIP: {SO} not built (run `make -C pkcs11`)")
        return 0

    sock = os.path.join(tempfile.gettempdir(), f"iztv-{os.getpid()}.sock")
    if len(sock) > 100:  # AF_UNIX limit
        sock = os.path.expanduser(f"~/.cache/iztv-{os.getpid()}.sock")
    env = dict(os.environ, IZENPE_TV_SOCK=sock, PYTHONPATH=os.path.join(ROOT, "src"))
    agent = subprocess.Popen([sys.executable, "-m", "izenpe_tv.agent", "--mock",
                              "--socket", sock], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        os.environ["IZENPE_TV_SOCK"] = sock
        lib = C.CDLL(SO)

        def ck(rv, where):
            assert rv == 0, f"{where} -> 0x{rv:08x}"

        ck(lib.C_Initialize(None), "Initialize")
        n = CK_ULONG(0)
        ck(lib.C_GetSlotList(1, None, C.byref(n)), "GetSlotList")
        slots = (CK_ULONG * n.value)()
        ck(lib.C_GetSlotList(1, slots, C.byref(n)), "GetSlotList2")
        sess = CK_ULONG(0)
        ck(lib.C_OpenSession(slots[0], CKF_SERIAL_SESSION, None, None, C.byref(sess)), "OpenSession")

        def find(cls):
            oc = CK_ULONG(cls)
            t = (CK_ATTRIBUTE * 1)()
            t[0].type = CKA_CLASS
            t[0].pValue = C.cast(C.byref(oc), C.c_void_p)
            t[0].ulValueLen = C.sizeof(oc)
            ck(lib.C_FindObjectsInit(sess, t, 1), "FindInit")
            h = (CK_ULONG * 16)()
            cnt = CK_ULONG(0)
            ck(lib.C_FindObjects(sess, h, 16, C.byref(cnt)), "Find")
            ck(lib.C_FindObjectsFinal(sess), "FindFinal")
            return [h[i] for i in range(cnt.value)]

        certs, keys = find(CKO_CERTIFICATE), find(CKO_PRIVATE_KEY)
        assert certs and keys, "no objects enumerated"

        # Regression: every template attribute must match. NSS looks up issuers by
        # CKA_SUBJECT and keys by CKA_ID for each root CA; answering those with our
        # objects made Firefox hang (it believed every root had a private key here).
        def find_tmpl(attrs):
            t = (CK_ATTRIBUTE * len(attrs))()
            keep = []
            for i, (typ, val) in enumerate(attrs):
                b = (C.c_ubyte * len(val)).from_buffer_copy(val)
                keep.append(b)
                t[i].type, t[i].pValue, t[i].ulValueLen = typ, C.cast(b, C.c_void_p), len(val)
            ck(lib.C_FindObjectsInit(sess, t, len(attrs)), "FindInit tmpl")
            h = (CK_ULONG * 16)()
            cnt = CK_ULONG(0)
            ck(lib.C_FindObjects(sess, h, 16, C.byref(cnt)), "Find tmpl")
            ck(lib.C_FindObjectsFinal(sess), "FindFinal tmpl")
            return cnt.value
        cls_cert = bytes(CK_ULONG(CKO_CERTIFICATE))
        cls_priv = bytes(CK_ULONG(CKO_PRIVATE_KEY))
        CKA_SUBJECT = 0x101
        assert find_tmpl([(CKA_CLASS, cls_cert), (CKA_SUBJECT, b"\x30\x00")]) == 0
        assert find_tmpl([(CKA_CLASS, cls_priv), (CKA_ID, b"\x00" * 20)]) == 0
        assert find_tmpl([(CKA_CLASS, 0xCE534353 .to_bytes(C.sizeof(CK_ULONG), "little"))]) == 0

        def getval(h, typ):
            a = (CK_ATTRIBUTE * 1)()
            a[0].type = typ
            ck(lib.C_GetAttributeValue(sess, h, a, 1), "attr size")
            buf = (C.c_ubyte * a[0].ulValueLen)()
            a[0].pValue = C.cast(buf, C.c_void_p)
            ck(lib.C_GetAttributeValue(sess, h, a, 1), "attr val")
            return bytes(buf[:a[0].ulValueLen])

        der = getval(certs[0], CKA_VALUE)
        kid = getval(keys[0], CKA_ID)
        assert find_tmpl([(CKA_CLASS, cls_priv), (CKA_ID, kid)]) == 1
        msg = b"izenpe pkcs11 smoke test"
        mech = CK_MECHANISM(CKM_SHA256_RSA_PKCS, None, 0)
        ck(lib.C_SignInit(sess, C.byref(mech), keys[0]), "SignInit")
        mbuf = (C.c_ubyte * len(msg)).from_buffer_copy(msg)
        sl = CK_ULONG(0)
        ck(lib.C_Sign(sess, mbuf, len(msg), None, C.byref(sl)), "Sign size")
        sig = (C.c_ubyte * sl.value)()
        ck(lib.C_Sign(sess, mbuf, len(msg), sig, C.byref(sl)), "Sign")
        sig = bytes(sig[:sl.value])

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        x509.load_der_x509_certificate(der).public_key().verify(
            sig, msg, padding.PKCS1v15(), hashes.SHA256())

        ck(lib.C_CloseSession(sess), "CloseSession")
        ck(lib.C_Finalize(None), "Finalize")
        print("PASS: PKCS#11 module sign+verify via mock agent")
        return 0
    finally:
        agent.terminate()
        if os.path.exists(sock):
            os.unlink(sock)


if __name__ == "__main__":
    sys.exit(main())
