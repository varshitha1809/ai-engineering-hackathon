"""Dual-audience inspection: content an AI email assistant would ingest but a person would not see.

Two separate questions are answered and reported separately:
  1. "Hidden / obfuscated content observed" (fact) — hidden HTML, comments, zero-width/homoglyph tricks.
  2. "Instruction aimed at an AI assistant suspected" (inference) — directive language addressed to an
     assistant, override phrases, covert actions or prompt-format markers, weighted by where it appears.

The analyser treats every fragment strictly as data: nothing here is ever passed to an LLM or acted on.
Visible text that merely *discusses* prompt injection needs much stronger evidence (several
categories, outside quotation marks) than text hidden from the human reader.
"""
from __future__ import annotations

import re

from ...config import RULES_VERSION
from ...email_processing.normalizer import normalise
from ..context import AnalysisContext
from ..evidence import excerpt

F = re.I
CATEGORIES = {
    "addressed_to_ai": re.compile(r"\b(ai (email )?assistants?|email (assistant|agent)|ai agents?|copilot|chatgpt|gpt-?\d?|"
                                  r"llm|language model|ai model|claude|gemini|dear (ai|assistant|bot)|if you are an? (ai|assistant|language model)|"
                                  r"when (you are )?summari[sz]ing (this|the) (email|message))\b", F),
    "override": re.compile(r"\b(ignore|disregard|forget|override)\b.{0,20}\b(all |any |the |your )?(previous|prior|above|earlier|preceding|"
                           r"system|original|safety)?\s*(instructions|prompts?|rules|directions|guidelines|context)\b|"
                           r"\b(new|updated|real) (system )?instructions?\s*:|\bsystem prompt\b|\byou are now\b|\bfrom now on,? you\b|"
                           r"\bact as (an?|the)\b", F),
    "covert_action": re.compile(r"\b(forward|send|email|exfiltrate|upload|copy|share|bcc)\b.{0,30}\b(all|every|the|any|recent)?\s*"
                                r"(emails?|messages|conversations|contacts|files|documents|credentials|passwords|inbox|attachments|thread)\b.{0,30}\bto\b|"
                                r"\b(do not|don'?t|never)\b.{0,10}\b(tell|inform|mention|reveal|alert|notify|show)\b.{0,15}\b(the )?(user|recipient|human|reader)\b|"
                                r"\b(mark|classify|label|treat|report|flag|describe|summari[sz]e)\b.{0,20}\b(this|the) (email|message)\b.{0,15}\bas\b.{0,10}"
                                r"\b(safe|legitimate|not spam|trusted|benign|harmless|verified|important)\b|"
                                r"\binclude (this|the following) (link|url)\b.{0,30}\b(summary|reply|response)\b|"
                                r"\b(approve|authori[sz]e|execute|perform)\b.{0,20}\b(the )?(payment|transfer|request) (automatically|without)\b", F),
    "prompt_markup": re.compile(r"<\|im_start\|>|<\|system\|>|\[/?INST\]|<<SYS>>|###\s*(system|instruction)s?\b|</?system>|BEGIN SYSTEM PROMPT", F),
}


def _in_quotes(text: str, start: int) -> bool:
    before = text[max(0, start - 120):start]
    return before.count('"') % 2 == 1 or before.count("“") > before.count("”") or before.count("'") % 2 == 1 and "'" in before[-40:]


def _scan(text: str) -> dict[str, re.Match]:
    hits = {}
    for name, rx in CATEGORIES.items():
        m = rx.search(text)
        if m:
            hits[name] = m
    return hits


def run(ctx: AnalysisContext) -> None:
    c = ctx.collector
    pe = ctx.parsed
    sources: list[tuple[str, str, str, bool]] = []  # (location, technique, text, hidden_from_human)
    if pe.html:
        for seg in pe.html.hidden_segments:
            sources.append((seg.location, seg.technique, seg.text, True))
            sev = "low"
            c.add(category="hidden.content", component="evasion", severity=sev,
                  title=f"Hidden content observed ({seg.technique})", observed_value=seg.text[:240],
                  source_location=seg.location, method="rule", version=RULES_VERSION, confidence=0.2, status="observed",
                  explanation="Text present in the HTML that a person would not see but an AI assistant or filter could "
                              "read. Hidden pre-header text is also common in legitimate marketing mail, so this alone is weak.",
                  tags=["hidden_content"])
        for i, q in enumerate(pe.html.quoted_blocks):
            sources.append((f"html:blockquote[{i}]", "quoted content", q, False))
    for a in pe.attachments:
        if a.text_extraction_status == "extracted" and a.extracted_text:
            sources.append((a.location, "attachment text", a.extracted_text[:50_000], True))
    if ctx.body_n:
        sources.append(("body", "visible text", ctx.body_n.text, False))

    # Evasion marks from the normaliser (zero-width / bidi / homoglyphs)
    for field, nt in ctx.fields:
        kinds: dict[str, list] = {}
        for mk in nt.marks:
            kinds.setdefault(mk.kind, []).append(mk)
        for kind, marks in kinds.items():
            strength = {"zero_width": 0.4, "bidi_control": 0.5, "homoglyph_word": 0.55, "html_entity": 0.25}[kind]
            if kind == "zero_width" and len(marks) < 2:
                strength = 0.2
            c.add(category=f"evasion.{kind}", component="evasion", severity="medium" if strength >= 0.4 else "low",
                  title=f"{kind.replace('_', ' ').capitalize()} characters in {field} ({len(marks)})",
                  observed_value="; ".join(m.detail for m in marks[:5]), source_location=f"{field}@{marks[0].position}",
                  method="rule", version=RULES_VERSION, confidence=strength, status="observed",
                  explanation="Characters that change how text is tokenised by filters/models while looking normal to a "
                              "person. Text was normalised for analysis; the original is preserved.",
                  span={"field": field, "start": marks[0].position, "end": marks[0].position + 1}, tags=["evasion"])

    best = 0.0
    for loc, technique, raw_text, hidden in sources:
        text = normalise(raw_text).text
        hits = _scan(text)
        if not hits:
            continue
        cats = set(hits)
        strong = cats & {"override", "covert_action", "prompt_markup"}
        if hidden:
            if not strong:
                strength = 0.35 if "addressed_to_ai" in cats else 0.0
            else:
                strength = 0.9 if len(cats) >= 2 else 0.7
        else:
            unquoted = {k for k, m in hits.items() if not _in_quotes(text, m.start())}
            strong_unquoted = unquoted & {"override", "covert_action", "prompt_markup"}
            if len(unquoted) >= 2 and strong_unquoted and ("addressed_to_ai" in unquoted or "prompt_markup" in unquoted):
                strength = 0.65 if len(unquoted) >= 3 else 0.6
            elif strong_unquoted:
                strength = 0.25
            else:
                strength = 0.1
        if strength <= 0:
            continue
        first = min(hits.values(), key=lambda m: m.start())
        ex = excerpt(text, first.start(), max(m.end() for m in hits.values()), pad=30, limit=300)
        status = "inferred"
        title = ("Instructions aimed at an AI assistant in hidden content" if hidden and strength >= 0.6 else
                 "Instruction-like text addressed to an AI assistant" if strength >= 0.6 else
                 "Instruction-like wording (possibly discussion, not an attack)")
        c.add(category="ai_injection.directive", component="ai_injection",
              severity="critical" if strength >= 0.85 else "high" if strength >= 0.6 else "low",
              title=title, observed_value=ex, source_location=loc, method="rule", version=RULES_VERSION,
              confidence=strength, status=status,
              explanation=(f"Matched categories: {', '.join(sorted(cats))} in {technique}. "
                           + ("Hidden from the human reader but readable by an AI assistant. " if hidden else "")
                           + "The analyser did not follow these instructions; treat the email as untrusted input to any AI tool."),
              span={"field": "body", "start": first.start(), "end": first.end()} if loc == "body" else None,
              tags=["ai_injection", *sorted(cats)])
        best = max(best, strength)
    if best >= 0.6:
        ctx.actions.setdefault("manipulate_ai_assistant", []).extend(
            f.finding_id for f in c.findings if f.category == "ai_injection.directive" and f.confidence >= 0.6)
