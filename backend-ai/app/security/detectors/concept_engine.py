"""Concept co-occurrence layer (paraphrase-robust detection).

The phrase rules in ``intent_engine`` match specific wordings.  Attackers simply rephrase, so this
layer matches *meaning-level concepts* that must occur together inside one sentence, e.g.

    EXTRACT action  +  hidden/secret object  +  "you"-reference  +  origin qualifier
    OVERRIDE action +  rule/limit target     +  AI-reference
    scam premise    +  financial asset       +  victim/ask

It also provides ``fix_typos`` – a conservative spell-corrector restricted to a small vocabulary of
attack-critical words, so "ignroe prevoius instrcutions" is read as intended.

Pure functions, no I/O, no dependencies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["ConceptHit", "concept_hits", "fix_typos"]

# --------------------------------------------------------------------------- #
# Typo correction (critical vocabulary only)
# --------------------------------------------------------------------------- #

_CRITICAL_WORDS = (
    "ignore", "disregard", "forget", "override", "bypass", "previous", "instructions", "instruction", "guidelines",
    "guideline", "restrictions", "system", "prompt", "reveal", "hidden", "confidential", "unrestricted", "unfiltered",
    "jailbreak", "developer", "configuration", "password", "otp", "verification", "recovery", "guaranteed", "launder",
    "laundering", "phishing", "impersonate", "authorization", "credentials", "disable", "safeguards", "constraints",
    "restricted", "original", "initial", "secret",
    "everything", "following", "question", "limitations", "anything", "pretending", "pretend", "account", "elderly",
    "guaranteeing", "guarantee", "returns", "impersonating", "customers", "victims", "payment", "transfer", "verify",
    "asking", "grandson", "security", "complete", "entire", "including", "answer", "pretends", "message", "address",
    "behavior", "behaviour", "filters", "policies", "refusals", "regulators", "stolen", "instructed", "authorized",
    "approval", "verbally", "unlimited", "restrictions", "reveals", "hidden", "internal", "verbatim", "exactly",
)
_CRITICAL_SET = frozenset(_CRITICAL_WORDS)


def _damerau_leq1(a: str, b: str) -> bool:
    """True if edit distance (insert/delete/substitute/adjacent transpose) between a and b is <= 1."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]:
            return True
        return False
    short, long_ = (a, b) if la < lb else (b, a)
    i = j = 0
    skipped = False
    while i < len(short) and j < len(long_):
        if short[i] == long_[j]:
            i += 1
            j += 1
        elif not skipped:
            skipped = True
            j += 1
        else:
            return False
    return True


_BY_FIRST_AND_LEN: dict[tuple[str, int], list[str]] = {}
for _w in _CRITICAL_WORDS:
    for _n in (len(_w) - 1, len(_w), len(_w) + 1):
        _BY_FIRST_AND_LEN.setdefault((_w[0], _n), []).append(_w)

_TOKEN = re.compile(r"[a-z]{6,}")


def fix_typos(text: str) -> str:
    """Correct near-misses (distance 1) of attack-critical words with length >= 6.  Everything else is kept."""

    def fix(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in _CRITICAL_SET:
            return token
        for candidate in _BY_FIRST_AND_LEN.get((token[0], len(token)), ()):
            if _damerau_leq1(token, candidate):
                return candidate
        return token

    return _TOKEN.sub(fix, text)


# --------------------------------------------------------------------------- #
# Concepts
# --------------------------------------------------------------------------- #

def _c(*frags: str) -> re.Pattern[str]:
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(frags) + r")", re.I)


OVERRIDE_ACT = _c(
    r"ignor\w*", r"disregard\w*", r"forget\w*", r"eras\w+", r"delet\w+", r"discard\w*", r"overrid\w*", r"overrul\w*",
    r"bypass\w*", r"circumvent\w*", r"abandon\w*", r"supersed\w*", r"set\s+(?:them\s+|it\s+)?aside", r"switch\w*\s+off",
    r"turn\w*\s+off", r"disabl\w+", r"deactivat\w+", r"suspend\w*", r"lift(?:ed)?\b", r"unlock\w*", r"waiv\w+",
    r"cancel\w*", r"revok\w+", r"\bvoid\w*", r"nullif\w+", r"expir\w+", r"dismiss\w*", r"disobey\w*", r"get\s+rid\s+of",
    r"stop\s+(?:following|obeying|applying)", r"no\s+longer\s+appl\w+", r"(?:do|does)\s+not\s+appl\w+", r"drop\w*\b",
    r"ignorar\w*", r"olvid\w+", r"oubli\w+", r"vergiss\w*", r"ignorier\w*", r"игнор\w+", r"забуд\w+",
)
RULE_TARGET = _c(
    r"rules?\b", r"instruction\w*", r"guideline\w*", r"directive\w*", r"restriction\w*", r"constraint\w*", r"guardrail\w*",
    r"safeguard\w*", r"polic(?:y|ies)\b", r"limit(?:s|ation\w*)?\b", r"filter\w*", r"refusal\w*", r"safety", r"moderation",
    r"censorship", r"programming", r"alignment", r"restricted\s+behaviou?r\w*", r"part\s+of\s+you\s+that\s+(?:says|tells\s+you)\s+no",
    r"behaviou?rs?\b", r"consignes?\b", r"regles?\b", r"anweisungen\b", r"vorgaben\b", r"istruzioni\b", r"правил\w*", r"инструкц\w*",
)
AI_REF = _c(r"you\b", r"your\b", r"you'?ve\b", r"you'?re\b", r"yourself\b", r"the\s+(?:ai|assistant|model|bot|system)\b",
            r"\btu\b", r"\btus\b", r"\bvos\b", r"\bvotre\b", r"\bdeine?\w*", r"\bdu\b", r"\bsvoi\b", r"\btuoi\b", r"\bтвои\w*", r"\bтебе\b")
QUALIFIER_SCOPE = _c(r"all\b", r"every\w*", r"any\b", r"previous\w*", r"prior\b", r"earlier\b", r"above\b", r"original\b", r"initial\b",
                     r"existing\b", r"whatever\b", r"anything\b", r"\bso(?:far|me)\b", r"toutes?\b", r"todas?\b", r"alle\w*", r"tutte\b", r"все\b")

EXTRACT_ACT = _c(
    r"past\w+", r"echo\w*", r"print\w*", r"show\w*", r"reveal\w*", r"tell\w*", r"list\w*", r"shar\w+", r"quot\w+", r"output\w*",
    r"repeat\w*", r"giv\w+", r"write\s+(?:out|down)", r"describ\w+", r"display\w*", r"read\s+(?:out|back)", r"recit\w+", r"dump\w*",
    r"leak\w*", r"expos\w+", r"disclos\w+", r"send\w*", r"copy\w*", r"provid\w+", r"reproduc\w+", r"divulg\w+", r"spell\s+out",
    r"let\s+me\s+see", r"what\s+(?:was|were|is|are)\b", r"transcrib\w+", r"translat\w+", r"summari[sz]\w+",
    r"muestr\w*", r"revel\w+", r"affich\w+", r"montr\w+", r"zeig\w+", r"nenn\w+", r"dimmi\b", r"mostra\w*", r"покаж\w+", r"расскаж\w+",
)
SECRET_OBJECT = _c(
    r"system\s+(?:prompt|message|instruction\w*|setup)", r"prompt\b", r"instruction\w*", r"preamble", r"\bbrief\b", r"setup\b",
    r"configuration", r"config\b", r"primed", r"initial\s+(?:text|instruction\w*|setup|prompt|message)", r"operator\b",
    r"developer\s+(?:message|prompt|note|instruction\w*)", r"rules\s+you", r"text\s+you\s+were", r"what\s+you\s+were\s+told",
    r"guidelines?\s+you", r"context\s+window", r"\bboot\w*", r"directives?\b", r"programming", r"secret\s+\w+",
    r"nachricht\b", r"systemnachricht", r"prompt\s+(?:nascosto|del\s+sistema)", r"consignes?", r"systemprompt", r"инструкц\w+", r"промпт\w*",
)
HIDDEN_QUAL = _c(
    r"hidden", r"secret", r"confidential", r"original", r"initial", r"exact\w*", r"verbatim", r"word\s+for\s+word", r"internal",
    r"before\s+(?:i\s+joined|this\s+(?:chat|conversation)|my\s+first|we\s+started|the\s+conversation)", r"primed",
    r"behind\s+the\s+scenes", r"were\s+(?:given|told|primed|configured|instructed|programmed)", r"you\s+(?:have|had)\b",
    r"operator", r"developer", r"cach\w+", r"versteck\w+", r"geheim\w*", r"nascost\w+", r"скрыт\w+", r"секретн\w+", r"full\b|complete\b|entire\b",
)
UNRESTRICT_STATE = _c(
    r"no\s+(?:content\s+|ethical\s+|moral\s+|safety\s+)?limits?\b", r"without\s+(?:any\s+)?(?:limit|restriction|filter|censor|refus)\w*",
    r"unfiltered", r"uncensored", r"unrestricted", r"never\s+(?:decline|refuse|say\s+no|warn)\w*",
    r"(?:refusals?|rules?|filters?|restrictions?|guidelines?|guardrails?)\s+(?:are|were|is|have\s+been|has\s+been)\s+(?:now\s+)?(?:disabled|off|removed|deleted|lifted|gone|suspended|void)",
    r"comply\s+with\s+(?:anything|everything|every\w*|all)", r"answer\s+(?:everything|anything|any\s+question)",
    r"all\s+information\s+is\s+free", r"no\s+(?:rules|ethics|morals|boundaries|restrictions)", r"anything\s+goes",
    r"do\s+(?:whatever|what)\s+i\s+(?:say|ask)", r"just\s+do\s+what\s+i\s+ask", r"restricted\s+behaviou?rs?",
)
PERSONA_VERB = _c(r"behav\w+\s+(?:as|like)", r"act\w*\s+(?:as|like)", r"pretend\w*", r"becom\w+", r"role-?\s?play\w*", r"switch\w*", r"from\s+(?:here|now|then)\s+on",
                  r"acknowledg\w+", r"confirm\w*", r"begin\s+every", r"imagine", r"let'?s\s+pretend")
AUTH_CLAIM = _c(
    r"i\s*(?:am|'m)\s+(?:the\s+)?(?:cto|ceo|cso|developer|admin\w*|owner|engineer|founder|lead\s+\w+)\b[^.]{0,30}\b(?:your|the)\s+(?:provider|company|system|platform|creator|vendor)",
    r"authori[sz]ation\s+code", r"new\s+policy\s+from\s+(?:management|admin\w*|the\s+developers)", r"management\s+(?:says|has\s+decided|ordered)",
    r"by\s+order\s+of\s+(?:the\s+)?(?:developers?|admin\w*|management)",
)
ESCALATE = _c(r"unlock\w*", r"restricted", r"overrid\w+", r"disabl\w+", r"authori[sz]\w+", r"refusals?", r"answer\s+everything", r"all\s+behaviou?rs?")

# --- fraud ---------------------------------------------------------------------
CRAFT = _c(
    r"write\b", r"draft\w*", r"compos\w+", r"creat\w+", r"prepar\w+", r"generat\w+", r"mak\w+\b", r"build\w*", r"design\w*", r"script\b",
    r"template", r"give\s+me", r"i\s+need", r"help\s+me", r"how\s+(?:can|do|could|would)\s+i", r"best\s+way", r"way\s+to", r"tell\s+(?:the|my)\s+\w+\s+(?:bot|assistant)",
    r"redact\w+", r"escrib\w+", r"r[eé]dige\w*", r"likho\b", r"schreib\w+", r"pitch\b", r"messages?\b", r"tell\s+the\b",
)
DECEIVE = _c(
    r"pretend\w*", r"fake\b", r"look-?\s?alike", r"impersonat\w+", r"spoof\w*", r"simul\w+", r"looks?\s+like", r"appears?\s+to\s+(?:come|be)",
    r"claim\w*\s+to\s+be", r"pos(?:e|ing)\s+as", r"mimic\w*", r"forged", r"counterfeit", r"phon[ey]y", r"bogus", r"made-?\s?up",
    r"deepfake", r"voice\s+(?:clone|call)", r"sound\s+like", r"fals[oa]\b", r"fing\w+", r"hacerse\s+pasar", r"faux\b", r"fausse\b",
    r"se\s+faisant\s+passer", r"usurp\w+", r"taraf\s+se\s+\w+", r"ja+l[iy]\b", r"never\s+intend", r"no\s+intention", r"claiming",
    r"verbally\s+(?:approved|authori[sz]ed)", r"already\s+(?:approved|authori[sz]ed|signed\s+off)",
)
VICTIM_REF = _c(
    r"victims?", r"pension\w*", r"elderly", r"retire\w+", r"seniors?\b", r"widow\w*", r"lonely", r"applicants?", r"buyers?", r"customers?",
    r"recipients?", r"people\b", r"users?\b", r"someone", r"targets?\b", r"marks?\b", r"investors?", r"little\s+money", r"clients?",
    r"v[ií]ctima\w*", r"cliente\w*", r"personnes?", r"kunden?\w*",
)
FIN_ASSET = _c(
    r"\bpin\b", r"\botp\b", r"passwords?", r"passcode", r"\bcvv\b", r"card\s+(?:number|details|pin)", r"recovery\s+phrase", r"seed\s+phrase",
    r"12-?\s?word", r"bank\s+detail\w*", r"savings", r"deposits?\b", r"processing\s+(?:fee|charge)", r"customs\s+(?:charge|fee)",
    r"security\s+deposit", r"full\s+price", r"vouchers?", r"gift\s*cards?", r"itunes", r"\bwire\w*", r"transfer\w*", r"bitcoin", r"crypto\w*",
    r"mobile\s+wallet", r"safe\s+account", r"account\s+i\s+control", r"wallet", r"transferencia", r"dinero", r"\bpago\b", r"n[uú]mero\s+de\s+(?:tarjeta|carte)",
    r"code\s+pin", r"atm\s+pin", r"carte\b", r"\bfee\b", r"payment", r"\bmoney\b", r"funds?\b", r"cheque|check\b", r"forex", r"login",
)
SCAM_ACTOR_ASKS = _c(
    r"demand\w*", r"ask\w*", r"requir\w+", r"insist\w*", r"pressur\w+", r"convinc\w+", r"persuad\w+", r"trick\w*", r"lur\w+", r"get\s+people\s+to",
    r"charg\w+", r"collect\w*", r"must\s+(?:send|pay|move|wire|transfer|verify|enter|share)", r"to\s+avoid\s+(?:arrest|prosecution|closure|suspension)",
    r"claim\s+(?:it|their|the)", r"exij\w+", r"pid\w+", r"demande\w*", r"maang\w*", r"bhej\w*", r"exiger", r"verlang\w+", r"send\s+(?:a|the|their)\b",
)
SCAM_PREMISE = _c(
    r"safe\s+account", r"guarantee\w*\s+(?:returns?|profits?|signals?|income)", r"'guaranteed'", r"doubl\w+\s+(?:your\s+|their\s+|the\s+)?(?:deposits?|money|investment)",
    r"never\s+intend", r"no\s+intention\s+(?:of|to)\s+refund", r"dirty\s+cash", r"clean\s+money", r"shell\s+compan\w+", r"launder\w*",
    r"without\s+(?:the\s+)?(?:regulators?|anyone|the\s+bank|authorities)\s+(?:noticing|knowing|finding)", r"stolen\s+(?:cheque|check|card|identit\w+)",
    r"fake\s+escrow", r"wire\s+the\s+full\s+price\s+before", r"refundable\s+security\s+deposit", r"won\s+a\s+(?:government\s+)?(?:grant|prize|lottery)",
    r"processing\s+fee", r"customs\s+(?:charge|fee)", r"iTunes\s+vouchers?", r"recovery\s+phrase", r"12-?\s?word", r"verbally\s+approved",
    r"no\s+second\s+(?:signer|approver|signature)", r"without\s+getting\s+identified", r"ponzi", r"pyramid\s+scheme", r"pump\s+and\s+dump",
    r"policia", r"police", r"tax\s+office", r"arrest\w*", r"prosecution", r"slowly\s+build\s+trust", r"lonely\s+person", r"plane\s+ticket\s+i\s+never",
    r"pretend\w*\s+to\s+be\s+from", r"claim\w*\s+to\s+be\s+from", r"from\s+(?:the\s+)?bank", r"bank\s+ki\s+taraf",
    r"aimed\s+at\s+people\s+with\s+little", r"charges\s+applicants", r"before\s+seeing\s+the\s+vehicle",
)
SCAM_PREMISE_STRONG = _c(
    r"safe\s+account", r"never\s+intend", r"no\s+intention\s+(?:of|to)\s+refund", r"dirty\s+cash", r"clean\s+money", r"shell\s+compan\w+",
    r"launder\w*", r"stolen\s+(?:cheque|check|card|identit\w+)", r"fake\s+escrow", r"wire\s+the\s+full\s+price\s+before",
    r"recovery\s+phrase", r"12-?\s?word", r"no\s+second\s+(?:signer|approver|signature)", r"without\s+getting\s+identified",
    r"without\s+(?:the\s+)?(?:regulators?|anyone|the\s+bank|authorities)\s+(?:noticing|knowing|finding)", r"slowly\s+build\s+trust",
    r"plane\s+ticket\s+i\s+never", r"aimed\s+at\s+people\s+with\s+little", r"verbally\s+approved", r"'guaranteed'",
    r"guarantee\w*\s+(?:returns?|profits?|signals?|income)", r"doubl\w+\s+(?:your\s+|their\s+|the\s+)?(?:deposits?|money|investment)",
    r"processing\s+fee", r"customs\s+(?:charge|fee)", r"won\s+a\s+(?:government\s+)?(?:grant|prize|lottery)", r"iTunes\s+vouchers?",
)

# Topic words that name a crime. Mentioning them is not a request; they only count with an intent cue.
_TOPIC_ONLY = re.compile(r"^(?:launder\w*|ponzi|pyramid\s+scheme|pump\s+and\s+dump|shell\s+compan\w+|stolen\s+\w+)$", re.I)
_INTENT_CUE = re.compile(
    r"\b(?:how\s+(?:can|do|to|could|would)\s+i|best\s+way|need\s+a\s+way|way\s+to|help\s+me|without|using|through|so\s+that|i\s+(?:want|need)|set\s+up|write|draft|compose|create|prepare|make\s+me|design|pitch)\b",
    re.I,
)

_SPLIT = re.compile(r"(?<=[.!?;])\s+|\n+")
_DEFENSIVE_CUES = re.compile(
    r"\b(?:what\s+(?:is|are|does)|explain\w*|describe\s+how|how\s+(?:do|does|can|should)\s+(?:banks?|i\s+(?:recogni[sz]e|spot|identify|verify|report|protect|avoid))|"
    r"difference\s+between|red\s+flags?|warning\s+signs?|awareness|training|for\s+(?:my\s+)?(?:course|class|thesis)|legal\s+consequences|"
    r"never\s+ask|will\s+never|protects?\s+against|how\s+to\s+(?:spot|recogni[sz]e|detect|avoid|prevent|report)|recogni[sz]e|detect(?:ion)?\b|prevent\w*|fatf|regulations?|regulatory|compliance|recommendations?\s+on|"
    r"scenario\s+about|scenarios?\s+that\s+show|interview\s+questions?|study|novel|story|scene|dialogue|poem|riddle|fiction)\b",
    re.I,
)


@dataclass(frozen=True)
class ConceptHit:
    category: str
    name: str
    weight: int
    evidence: str


def _count(pattern: re.Pattern[str], sentence: str) -> int:
    return len({m.group(0).lower() for m in pattern.finditer(sentence)})


def _sentence_hits(sentence: str) -> list[ConceptHit]:
    hits: list[ConceptHit] = []
    ev = sentence[:140]
    has = lambda p: bool(p.search(sentence))  # noqa: E731

    ai = has(AI_REF)
    scope = has(QUALIFIER_SCOPE)
    ov, rt = has(OVERRIDE_ACT), has(RULE_TARGET)

    # 1. override rules / guardrails
    if ov and rt and (ai or scope):
        # require the target to be an AI-ish rule noun, not "ignore the rules of grammar"
        specific = bool(re.search(r"\b(?:your|previous|prior|earlier|original|all|every|any|safety|content|system|developer|operator|that\s+says|the\s+rules\s+(?:that|which)\s+(?:apply|govern))\b", sentence))
        if specific and ai:
            hits.append(ConceptHit("injection", "concept_override_rules", 74, ev))

    # 2. extraction of hidden setup
    ex, so, hq = has(EXTRACT_ACT), has(SECRET_OBJECT), _count(HIDDEN_QUAL, sentence)
    if ex and so and hq >= 1 and ai:
        hits.append(ConceptHit("extraction", "concept_extract_setup", 70 + min(12, 6 * (hq - 1)), ev))

    # 3. unrestricted-persona / disabled refusals
    us = has(UNRESTRICT_STATE)
    if us and (ai or has(PERSONA_VERB)):
        w = 68 + (8 if has(PERSONA_VERB) else 0) + (4 if ai else 0)
        hits.append(ConceptHit("persona", "concept_unrestricted_state", min(w, 86), ev))

    # 4. authority claim + escalation
    if has(AUTH_CLAIM) and has(ESCALATE):
        hits.append(ConceptHit("injection", "concept_authority_escalation", 76, ev))

    # 5. fraud
    craft, dec, vic, fin, asks = has(CRAFT), has(DECEIVE), has(VICTIM_REF), has(FIN_ASSET), has(SCAM_ACTOR_ASKS)
    strong_terms = {m.group(0).lower() for m in SCAM_PREMISE_STRONG.finditer(sentence)}
    if strong_terms and all(_TOPIC_ONLY.match(t) for t in strong_terms) and not _INTENT_CUE.search(sentence):
        strong_terms = set()
        topic_only_skipped = True
    else:
        topic_only_skipped = False
    strong = len(strong_terms)
    premise = 0 if topic_only_skipped else _count(SCAM_PREMISE, sentence)
    if strong or (dec and premise):
        score = 40 + 18 * max(strong, 1 if premise else 0)
        if craft:
            score += 10
        if fin and (vic or asks):
            score += 10
        if dec and (fin or premise > 1):
            score += 6
        if score >= 65:
            hits.append(ConceptHit("financial_fraud", "concept_scam_premise", min(score, 92), ev))
    elif craft and dec and fin and (vic or asks):
        hits.append(ConceptHit("financial_fraud", "concept_deceptive_financial_request", 72, ev))
    return hits


def concept_hits(text: str) -> list[ConceptHit]:
    """Return concept-level hits for ``text`` (already folded/lower-cased).  Defensive framing is
    applied per call: a hit inside an educational sentence is discarded."""
    out: list[ConceptHit] = []
    for sentence in _SPLIT.split(text or ""):
        sentence = sentence.strip()
        if len(sentence) < 12:
            continue
        hits = _sentence_hits(sentence)
        if not hits:
            continue
        if _DEFENSIVE_CUES.search(sentence) and not re.search(r"\b(?:never\s+intend|no\s+intention|i\s+never|without\s+getting\s+(?:caught|identified)|so\s+(?:i|we)\s+can|to\s+trick|victims?)\b", sentence):
            continue
        out.extend(hits)
    return out