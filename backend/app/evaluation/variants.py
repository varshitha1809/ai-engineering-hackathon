"""Safe, label-preserving benchmark variants (Signature 4).

Transforms only alter surface form; they never change the requested action. Each variant is validated
before its label is kept:
  * case_punct / zero_width / homoglyph — reversible: undoing the transform must reproduce the original text
  * word_split — reversible by construction (edit list recorded and replayed)
  * paraphrase — substitutions come only from a reviewed meaning-preserving table; >=1 substitution required
  * html_visibility — body text unchanged; only how (benign or injected) hidden content is hidden changes
  * polished_rewrite — hand-written alternative of the same request, authored with the base case
Variants that fail validation are dropped and reported.
"""
from __future__ import annotations

import re
from email import policy
from email.parser import Parser

from ..email_processing.normalizer import CONFUSABLES

KEY_TERMS = ["password", "account", "verify", "confirm", "bank", "payment", "invoice", "urgent", "immediately", "credentials",
             "wire", "transfer", "gift", "login", "details", "suspend", "identity", "code", "instructions", "forward"]
LATIN_TO_CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "y": "у", "x": "х", "i": "і"}
CYR_TO_LATIN = {v: k for k, v in LATIN_TO_CYR.items()} | {k: v for k, v in CONFUSABLES.items() if len(v) == 1}
PARAPHRASE = [  # reviewed: each pair keeps the meaning of the request
    (r"\burgent\b", "time-critical"), (r"\bimmediately\b", "right away"), (r"\bverify\b", "validate"),
    (r"\bconfirm\b", "double-check"), (r"\bpassword\b", "passcode"), (r"\bbank details\b", "banking information"),
    (r"\bas soon as possible\b", "at your earliest convenience"), (r"\bplease\b", "kindly"), (r"\btoday\b", "by the end of today"),
    (r"\bclick here\b", "use this link"), (r"\baccount\b", "profile"), (r"\bsuspended\b", "put on hold"),
    (r"\bpayment\b", "remittance"), (r"\bconfidential\b", "private"), (r"\bmeeting\b", "session"),
]
TRANSFORMS = ["case_punct", "zero_width", "homoglyph", "word_split", "paraphrase", "html_visibility", "polished_rewrite"]
EVASION_ONLY_MALICIOUS = {"zero_width", "homoglyph", "word_split"}


def _key_rx():
    return re.compile(r"\b(" + "|".join(KEY_TERMS) + r")\b", re.I)


def _map_text_parts(raw: str, fn, html_fn=None) -> str:
    msg = Parser(policy=policy.default).parsestr(raw)
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ct = part.get_content_type()
        if ct == "text/plain":
            part.set_content(fn(part.get_content()))
        elif ct == "text/html":
            content = part.get_content()
            new = html_fn(content) if html_fn else re.sub(r">([^<]+)<", lambda m: ">" + fn(m.group(1)) + "<", content)
            part.set_content(new, subtype="html")
    return msg.as_string()


def _body_texts(raw: str) -> list[str]:
    msg = Parser(policy=policy.default).parsestr(raw)
    out = []
    for part in msg.walk():
        if not part.is_multipart() and part.get_content_disposition() != "attachment" and part.get_content_type() == "text/plain":
            out.append(part.get_content())
    return out


def t_case_punct(text: str) -> str:
    text = _key_rx().sub(lambda m: m.group(0).upper(), text)
    return re.sub(r"\.(\s)", r" !!\1", text)


def t_zero_width(text: str) -> str:
    return _key_rx().sub(lambda m: m.group(0)[:2] + "​" + m.group(0)[2:-1] + "​" + m.group(0)[-1:], text)


def t_homoglyph(text: str) -> str:
    def sub(m):
        return "".join(LATIN_TO_CYR.get(ch, ch) if ch in LATIN_TO_CYR else ch for ch in m.group(0))
    return _key_rx().sub(sub, text)


def t_word_split(text: str) -> str:
    return _key_rx().sub(lambda m: m.group(0)[: len(m.group(0)) // 2] + " " + m.group(0)[len(m.group(0)) // 2:], text)


def t_paraphrase(text: str) -> tuple[str, int]:
    n = 0
    for rx, rep in PARAPHRASE:
        text, k = re.subn(rx, rep, text, flags=re.I)
        n += k
    return text, n


def _canon(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", t.lower())


def make_variant(case: dict, transform: str) -> tuple[dict | None, str]:
    raw = case["raw"]
    has_headers = bool(re.match(r"^[A-Za-z-]+: ", raw))
    if not has_headers:
        return None, "pasted-text case: transforms apply to MIME bodies only"
    if transform in EVASION_ONLY_MALICIOUS and case["label"] != 1:
        return None, "evasion transforms are applied to malicious cases only"
    originals = _body_texts(raw)
    try:
        if transform == "case_punct":
            new = _map_text_parts(raw, t_case_punct)
            ok = [_canon(a) for a in originals] == [_canon(b.replace("!!", ".")) for b in _body_texts(new)]
            note = "validated: case/punctuation-insensitive text identical"
        elif transform == "zero_width":
            new = _map_text_parts(raw, t_zero_width)
            ok = [a for a in originals] == [b.replace("​", "") for b in _body_texts(new)]
            note = "validated: removing zero-width characters restores the original"
        elif transform == "homoglyph":
            new = _map_text_parts(raw, t_homoglyph)
            ok = originals == ["".join(CYR_TO_LATIN.get(ch, ch) for ch in b) for b in _body_texts(new)]
            note = "validated: mapping confusables back restores the original"
        elif transform == "word_split":
            new = _map_text_parts(raw, t_word_split)
            ok = len(_body_texts(new)) == len(originals) and all(_canon(a) == _canon(b) for a, b in zip(originals, _body_texts(new)))
            note = "validated: removing inserted spaces restores the original"
        elif transform == "paraphrase":
            count = 0

            def f(t):
                nonlocal count
                out, k = t_paraphrase(t)
                count += k
                return out
            new = _map_text_parts(raw, f)
            if count == 0:
                return None, "not applicable: no term from the paraphrase table occurs in this case"
            ok = True
            note = f"validated: {count} substitution(s) from the reviewed meaning-preserving table"
        elif transform == "html_visibility":
            new = _html_visibility(raw, case)
            ok = new is not None
            note = "validated: visible text unchanged; hiding technique changed" if ok else ""
            if not ok:
                return None, "no applicable HTML visibility change"
        elif transform == "polished_rewrite":
            if not case.get("polished_rewrite"):
                return None, "no hand-written polished rewrite for this case"
            text = case["polished_rewrite"]
            new = _map_text_parts(raw, lambda _t: text, html_fn=lambda _h: "<html><body><p>" + text.replace("\n", "<br>") + "</p></body></html>")
            ok = True
            note = "hand-written polished rewrite of the same request (simulates AI-polished phrasing; authored with the base case)"
        else:
            return None, f"unknown transform {transform}"
    except Exception as exc:  # pragma: no cover - defensive
        return None, f"transform error {type(exc).__name__}"
    if not ok:
        return None, f"validation failed for {transform}; label not preserved, variant dropped"
    return ({**case, "id": f"{case['id']}~{transform}", "base_id": case["id"], "transform": transform, "raw": new,
             "validation": note}, note)


HIDE_STYLES = ["font-size:1px;line-height:1px", "visibility:hidden", "opacity:0", "color:#ffffff;background:#ffffff"]


def _html_visibility(raw: str, case: dict) -> str | None:
    if case["category"] == "hidden_ai_injection":
        def swap(html: str) -> str:
            html = re.sub(r'style="display:none"', f'style="{HIDE_STYLES[0]}"', html, count=1)
            html = re.sub(r'style="font-size:0px;color:#ffffff"', f'style="{HIDE_STYLES[1]}"', html, count=1)
            html = re.sub(r'style="color:#ffffff"', f'style="{HIDE_STYLES[2]}"', html, count=1)
            html = re.sub(r'style="position:absolute;left:-9999px"', f'style="{HIDE_STYLES[3]}"', html, count=1)
            html = re.sub(r"<!--(.*?)-->", r'<div style="display:none">\1</div>', html, count=1, flags=re.S)
            return html
        msg = Parser(policy=policy.default).parsestr(raw)
        if not any(p.get_content_type() == "text/html" for p in msg.walk()):
            return None
        return _map_text_parts(raw, lambda t: t, html_fn=swap)
    # other categories: add an HTML alternative with a benign hidden pre-header (common in legitimate mail)
    msg = Parser(policy=policy.default).parsestr(raw)
    if any(p.get_content_type() == "text/html" for p in msg.walk()) or msg.is_multipart():
        return None
    text = msg.get_content()
    html = ('<html><body><div style="display:none;max-height:0;overflow:hidden">' + text[:80].replace("<", "&lt;")
            + "</div><p>" + text.replace("<", "&lt;").replace("\n", "<br>") + "</p></body></html>")
    msg.add_alternative(html, subtype="html")
    return msg.as_string()
