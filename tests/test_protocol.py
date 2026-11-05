import base64
import hashlib

from izenpe_tv import api, config, oauth


def test_authorize_url_has_required_params():
    env = config.ENVIRONMENTS["profesional"]
    url, state = oauth.build_authorize_url(env, login_hint="12345678Z")
    assert url.startswith("https://eidas-prof.izenpe.eus/trustedx-authserver/oauth/izenpe?")
    assert "response_type=code" in url
    assert "redirect_uri=oauth-swift" in url
    assert "bak_otp" in url
    assert state in url
    assert "login_hint=12345678Z" in url


def test_parse_redirect_ok_and_state():
    code = oauth.parse_redirect("oauth-swift://oauth-callback?code=ABC123&state=xyz",
                                expected_state="xyz")
    assert code == "ABC123"


def test_parse_redirect_state_mismatch():
    try:
        oauth.parse_redirect("oauth-swift://oauth-callback?code=A&state=bad",
                             expected_state="good")
    except oauth.OAuthError:
        pass
    else:
        raise AssertionError("expected state mismatch error")


def test_token_expiry():
    t = oauth.Token(access_token="x", expires_in=100, obtained_at=0)
    assert t.is_expired()
    t2 = oauth.Token.from_dict({"access_token": "x", "expires_in": 0})
    assert not t2.is_expired()


def test_sign_identity_label_classification():
    prof = api.SignIdentity("1", ["CIF:A12345678"], {})
    assert prof.is_profesional and prof.cif == "A12345678"
    cit = api.SignIdentity("2", ["bakq"], {})
    assert cit.is_ciudadano


def test_sign_raw_body_uses_digest_value_for_raw_sha256():
    captured = {}

    class FakeResp:
        status_code = 200
        def json(self):
            return {"signature": base64.b64encode(b"SIG").decode()}

    class FakeSession:
        def post(self, url, json=None, headers=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return FakeResp()

    env = config.ENVIRONMENTS["profesional"]
    c = api.ApiClient(env, "tok", session=FakeSession())
    digest = hashlib.sha256(b"hello").digest()
    sig = c.sign_raw("id-1", digest, algorithm="rsa-sha256")
    assert sig == b"SIG"
    assert captured["json"]["signature_algorithm"] == "rsa-sha256"
    assert "digest_value" in captured["json"]
    assert base64.b64decode(captured["json"]["digest_value"]) == digest
    assert captured["url"].endswith("/trustedx-resources/esigp/v1/signatures/server/raw")


def test_decode_signature_variants():
    assert api._decode_signature(base64.b64encode(b"A").decode()) == b"A"
    assert api._decode_signature({"bytes": [65, 66]}) == b"AB"
    assert api._decode_signature({"signature": base64.b64encode(b"C").decode()}) == b"C"
