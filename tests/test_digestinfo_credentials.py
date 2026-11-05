"""DigestInfo parsing (agent) and credential discovery heuristic (credentials)."""
import hashlib

from izenpe_tv.agent import _parse_digestinfo, _prepare_digest
from izenpe_tv.api import _DIGESTINFO_PREFIX
from izenpe_tv.credentials import find_credentials


def test_digestinfo_with_and_without_null_params():
    h = hashlib.sha256(b"x").digest()
    with_null = _DIGESTINFO_PREFIX["sha256"] + h                      # 51 bytes (RFC 8017)
    no_null = bytes.fromhex("302f300b06096086480165030402010420") + h  # 49 bytes (Idazki)
    for d in (with_null, no_null):
        assert _prepare_digest("CKM_RSA_PKCS", None, d) == (h, "rsa-sha256", False)


def test_digestinfo_all_hashes_and_garbage():
    for name, prefix in _DIGESTINFO_PREFIX.items():
        x = hashlib.new(name, b"y").digest()
        assert _parse_digestinfo(prefix + x) == (name, x)
    assert _parse_digestinfo(b"") is None
    assert _parse_digestinfo(b"\x30\x03abc") is None
    raw = hashlib.sha256(b"z").digest()
    assert _prepare_digest("CKM_RSA_PKCS", None, raw) == (raw, "rsa-sha256", False)


def test_find_credentials_layout():
    blob = b"\0".join([b"junk", b"app_locale", b"myclient1", b"oauth_profile", b"legacy",
                       b"OAuth profile: ", b"ideable", b"1d34bl3_g1ltz4", b"Abc123defG",
                       b"Zyx987wvuT", b"RemoveAllIzenpeCertificates - removing"])
    assert find_credentials(blob) == ("myclient1", ["Abc123defG", "Zyx987wvuT"])
    assert find_credentials(b"nothing here") == (None, [])


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
