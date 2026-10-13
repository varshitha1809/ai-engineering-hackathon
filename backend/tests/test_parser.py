import base64

import pytest

from backend.app.email_processing.html_inspector import inspect_html
from backend.app.email_processing.normalizer import normalise
from backend.app.email_processing.parser import EmailParseError, looks_like_rfc822, parse_input
from backend.app.email_processing.urls import normalise_url

from .conftest import eml

LIMIT = 5 * 1024 * 1024


def test_plain_text_paste_has_no_headers():
    pe = parse_input(b"Hello team, lunch at noon?", "paste", LIMIT)
    assert not pe.headers_present
    assert pe.visible_text.startswith("Hello team")
    assert pe.stage_status["mime"]["status"] == "skipped"


def test_pasted_rfc822_is_detected_and_parsed():
    raw = b"From: A <a@x.example>\nTo: b@y.example\nSubject: hi\n\nbody text"
    assert looks_like_rfc822(raw.decode())
    pe = parse_input(raw, "paste", LIMIT)
    assert pe.headers_present and pe.from_addr == "a@x.example" and pe.subject == "hi"


def test_html_plain_alternative_and_multipart():
    raw = eml({"From": "a@x.example", "Subject": "s"}, "plain part", html="<p>html part <a href='https://x.example/a'>link</a></p>")
    pe = parse_input(raw, "eml", LIMIT)
    assert "plain part" in pe.text_body and "html part" in pe.html_body
    assert any(u.url == "https://x.example/a" for u in pe.urls)
    assert {p["content_type"] for p in pe.parts} >= {"text/plain", "text/html"}


def test_quoted_printable_and_base64_decoding():
    qp = (b"From: a@x.example\nSubject: qp\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n"
          b"Content-Transfer-Encoding: quoted-printable\n\nPlease verify your acc=\nount =C3=A9 today")
    pe = parse_input(qp, "eml", LIMIT)
    assert "verify your account é today" in pe.text_body
    b64 = base64.b64encode("Base64 body with password reset".encode()).decode()
    raw = f"From: a@x.example\nSubject: b\nMIME-Version: 1.0\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n{b64}\n".encode()
    assert "password reset" in parse_input(raw, "eml", LIMIT).text_body


def test_malformed_mime_and_missing_headers_do_not_crash():
    raw = (b"From: broken\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"zzz\"\n\n"
           b"--zzz\nContent-Type: text/plain\n\nunterminated part without closing boundary")
    pe = parse_input(raw, "eml", LIMIT)
    assert pe.headers_present
    assert pe.from_addr == "" or "@" not in pe.from_addr
    assert pe.defects  # stdlib defects are recorded, not hidden


def test_oversized_and_empty_inputs_rejected():
    with pytest.raises(EmailParseError):
        parse_input(b"x" * 101, "paste", 100)
    with pytest.raises(EmailParseError):
        parse_input(b"   ", "paste", 100)


def test_attachment_inventory_hash_and_magic():
    raw = eml({"From": "a@x.example", "Subject": "s"}, "see attached",
              attachments=[("invoice.pdf", "application/pdf", b"MZ\x90\x00binary")])
    pe = parse_input(raw, "eml", LIMIT)
    a = pe.attachments[0]
    assert a.extension == "pdf" and a.detected_type == "application/x-dosexec" and len(a.sha256) == 64


def test_hidden_html_is_separated_from_visible_text():
    rep = inspect_html('<p>Visible</p><div style="display:none">secret directive</div><!-- comment text -->'
                       '<span style="color:#ffffff">white text</span>')
    assert "secret directive" not in rep.visible_text and "Visible" in rep.visible_text
    techniques = {h.technique for h in rep.hidden_segments}
    assert "display:none" in techniques and "HTML comment" in techniques
    assert any("colour equals background" in t for t in techniques)


def test_normaliser_preserves_original_and_marks_evasion():
    original = "p​ass​word for your аccount"  # zero-width + Cyrillic 'а'
    n = normalise(original)
    assert n.original == original
    assert "password" in n.text and "account" in n.text
    kinds = {m.kind for m in n.marks}
    assert {"zero_width", "homoglyph_word"} <= kinds
    s, e = n.to_original(n.text.index("account"), n.text.index("account") + 7)
    assert original[s:e] == "аccount"


def test_digits_are_not_homoglyphs():
    assert not normalise("IBAN 6016 1331 2026").marks


def test_url_normalisation_handles_idn_ip_and_userinfo():
    assert normalise_url("http://xn--pypal-4ve.com/login").host != "xn--pypal-4ve.com"
    assert normalise_url("http://192.0.2.4/x").is_ip
    assert normalise_url("https://paypal.com@evil.example/").has_userinfo
    assert not normalise_url("http://[::1").valid
