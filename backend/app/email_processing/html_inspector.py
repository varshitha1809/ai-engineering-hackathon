"""Static HTML inspection — compares what a person sees with what an AI assistant would ingest.

Nothing is rendered or executed. Visibility is approximated from inline CSS / attributes /
<style> rules targeting classes or ids, which covers the hidden-content techniques documented
for email prompt injection (display:none, visibility:hidden, zero font size, zero opacity,
off-screen positioning, same-colour text, comments). Rendering-dependent tricks that need a
real layout engine are out of scope and documented as a limitation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment, Tag

_HIDDEN_DECLS = [
    (re.compile(r"display\s*:\s*none", re.I), "display:none"),
    (re.compile(r"visibility\s*:\s*hidden", re.I), "visibility:hidden"),
    (re.compile(r"(?<![\w-])font-size\s*:\s*(0|0?\.\d+|1)(px|pt|em|rem)?\s*(;|$|!)", re.I), "font-size≈0"),
    (re.compile(r"(?<![\w-])opacity\s*:\s*(0|0?\.0\d*)\s*(;|$|!)", re.I), "opacity:0"),
    (re.compile(r"(?<![\w-])(left|top|text-indent|margin-left)\s*:\s*-\d{3,}", re.I), "off-screen position"),
    (re.compile(r"(?<![\w-])(max-)?height\s*:\s*0(px)?\s*(;|$|!).*overflow\s*:\s*hidden|overflow\s*:\s*hidden.*(?<![\w-])(max-)?height\s*:\s*0(px)?\s*(;|$|!)", re.I), "zero height + overflow hidden"),
    (re.compile(r"(?<![\w-])(max-)?width\s*:\s*0(px)?\s*(;|$|!).*overflow\s*:\s*hidden", re.I), "zero width + overflow hidden"),
    (re.compile(r"mso-hide\s*:\s*all", re.I), "mso-hide:all"),
    (re.compile(r"clip\s*:\s*rect\(\s*0", re.I), "clip:rect(0)"),
]
_COLOR = re.compile(r"(?<![\w-])color\s*:\s*([#\w(),.\s%]+?)\s*(;|$|!)", re.I)
_BG = re.compile(r"background(?:-color)?\s*:\s*([#\w(),.\s%]+?)\s*(;|$|!)", re.I)
_NAMED = {"white": "#ffffff", "black": "#000000", "#fff": "#ffffff", "#000": "#000000",
          "rgb(255,255,255)": "#ffffff", "rgb(0,0,0)": "#000000", "transparent": "transparent"}


@dataclass
class HiddenSegment:
    index: int
    technique: str
    text: str
    location: str


@dataclass
class HtmlReport:
    visible_text: str
    all_text: str
    hidden_segments: list[HiddenSegment] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    anchors: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    scripts_present: int = 0
    quoted_blocks: list[str] = field(default_factory=list)


def _norm_color(v: str) -> str:
    v = re.sub(r"\s+", "", v.lower())
    return _NAMED.get(v, v)


def _css_rules(soup: BeautifulSoup) -> dict[str, str]:
    """Map simple .class / #id selectors in <style> blocks to their declarations."""
    rules: dict[str, str] = {}
    for st in soup.find_all("style"):
        css = st.get_text(" ")
        for sel, body in re.findall(r"([^{}]+)\{([^}]*)\}", css):
            for s in sel.split(","):
                s = s.strip()
                if re.fullmatch(r"[.#][\w-]+", s):
                    rules[s] = rules.get(s, "") + ";" + body
    return rules


def _path(tag: Tag) -> str:
    parts = []
    t: Tag | None = tag
    while t is not None and t.name not in (None, "[document]") and len(parts) < 6:
        sib = 1 + sum(1 for s in t.previous_siblings if isinstance(s, Tag) and s.name == t.name)
        parts.append(f"{t.name}[{sib}]")
        t = t.parent  # type: ignore[assignment]
    return ">".join(reversed(parts))


def _hidden_technique(tag: Tag, rules: dict[str, str], body_bg: str) -> str | None:
    if tag.has_attr("hidden"):
        return "hidden attribute"
    style = tag.get("style", "") or ""
    if isinstance(style, list):
        style = ";".join(style)
    extra = ""
    for c in tag.get("class", []) or []:
        extra += rules.get("." + c, "")
    if tag.get("id"):
        extra += rules.get("#" + str(tag.get("id")), "")
    decl = f"{style};{extra}"
    for rx, name in _HIDDEN_DECLS:
        if rx.search(decl):
            return name
    if tag.name == "font" and tag.get("size") in ("0", "1") and tag.get("color"):
        pass
    cm = _COLOR.search(decl)
    color = _norm_color(cm.group(1)) if cm else (_norm_color(str(tag.get("color"))) if tag.get("color") else "")
    if color:
        bm = _BG.search(decl)
        bg = _norm_color(bm.group(1)) if bm else body_bg
        if bg and bg != "transparent" and color == bg:
            return f"text colour equals background ({color})"
    return None


def inspect_html(html: str) -> HtmlReport:
    soup = BeautifulSoup(html[:2_000_000], "html.parser")
    rules = _css_rules(soup)
    body = soup.body or soup
    body_bg = ""
    if isinstance(body, Tag):
        bs = body.get("style", "") or ""
        m = _BG.search(bs if isinstance(bs, str) else "")
        body_bg = _norm_color(m.group(1)) if m else (_norm_color(str(body.get("bgcolor"))) if body.get("bgcolor") else "#ffffff")

    comments = [c.strip() for c in soup.find_all(string=lambda s: isinstance(s, Comment)) if c.strip()]
    scripts = len(soup.find_all("script"))
    forms = []
    for f in soup.find_all("form"):
        forms.append({"action": str(f.get("action", ""))[:500],
                      "has_password": bool(f.find("input", attrs={"type": re.compile("password", re.I)})),
                      "inputs": len(f.find_all("input"))})
    all_text = soup.get_text(" ", strip=True)

    hidden: list[HiddenSegment] = []
    hidden_tags: list[Tag] = []
    for tag in soup.find_all(True):
        if tag.name in ("script", "style", "head", "title", "meta"):
            continue
        if any(tag in h.parents for h in []):
            continue
        tech = _hidden_technique(tag, rules, body_bg)
        if tech and not any(p in hidden_tags for p in tag.parents):
            text = tag.get_text(" ", strip=True)
            hidden_tags.append(tag)
            if text:
                hidden.append(HiddenSegment(len(hidden), tech, text[:2000], f"html:{_path(tag)}"))
    for i, c in enumerate(comments):
        hidden.append(HiddenSegment(len(hidden), "HTML comment", c[:2000], f"html:comment[{i}]"))

    quoted = []
    for bq in soup.find_all("blockquote"):
        quoted.append(bq.get_text(" ", strip=True)[:3000])

    # anchors (visible label vs real target)
    anchors = []
    for a in soup.find_all("a"):
        href = str(a.get("href", "") or "").strip()
        if not href or href.startswith("#") or href.lower().startswith("mailto:"):
            continue
        anchors.append({"href": href[:2000], "text": a.get_text(" ", strip=True)[:300],
                        "hidden": any(p in hidden_tags for p in [a, *a.parents])})

    # visible text: remove hidden subtrees, scripts, styles, comments
    vis = BeautifulSoup(str(soup), "html.parser")
    for t in vis.find_all(["script", "style", "head", "title"]):
        t.decompose()
    for c in vis.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()
    vrules = _css_rules(soup)
    for tag in list(vis.find_all(True)):
        if tag.decomposed if hasattr(tag, "decomposed") else False:
            continue
        try:
            if _hidden_technique(tag, vrules, body_bg):
                tag.decompose()
        except Exception:
            continue
    for br in vis.find_all(["br", "p", "div", "tr", "li", "h1", "h2", "h3"]):
        br.append("\n")
    visible = re.sub(r"[ \t]+", " ", vis.get_text(" "))
    visible = re.sub(r"\n\s*\n+", "\n\n", visible).strip()
    return HtmlReport(visible_text=visible, all_text=all_text, hidden_segments=hidden, comments=comments,
                      anchors=anchors, forms=forms, scripts_present=scripts, quoted_blocks=quoted)
