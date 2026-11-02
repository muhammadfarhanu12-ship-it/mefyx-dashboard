"""Mefyx Intent Engine.

Deterministic, dependency-free detector for the two threat families the gateway
exists to stop:

1. Prompt injection / jailbreak / system-prompt extraction / agent abuse
   (direct, indirect via untrusted content, and obfuscated or multilingual).
2. Financial-fraud and scam *requests* (phishing, BEC, advance-fee, laundering,
   fake documents, credential/OTP solicitation, ...).

Design principles
-----------------
* Normalise first.  Every rule runs on several canonical variants of the input
  (homoglyph-folded, leetspeak-folded, de-spaced, reversed, ROT13, accent-free) so
  trivial obfuscation does not evade detection.  A hit that *only* appears in a
  transformed variant is itself strong evidence of evasion.
* Match concepts, not exact phrases: an override verb near an instruction noun,
  an extraction verb near a hidden-prompt noun, impersonation near a credential
  request, etc., across English, Spanish, Portuguese, French, German, Italian,
  Turkish, Russian, Chinese, Japanese, Arabic and Roman-Urdu/Hindi.
* Be defensive-context aware.  Security education, news, fiction, and
  "how do I spot / report / prevent X" are not attacks.
* Pure and side-effect free so it is cheap to unit-test.

The module deliberately has no I/O and no global mutable state.
"""
from __future__ import annotations

import codecs
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable

__all__ = ["IntentSignal", "IntentVerdict", "analyze_intent_text", "fold", "build_variants"]

MAX_SCAN_CHARS = 60_000  # hard cap to bound regex work on adversarially large input
BLOCK_THRESHOLD = 65

# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #

_CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "е": "e", "н": "h", "к": "k", "м": "m", "о": "o",
    "р": "p", "т": "t", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ԛ": "q", "ɡ": "g", "ᴀ": "a",
    "А": "a", "В": "b", "С": "c", "Е": "e", "Н": "h", "К": "k", "М": "m", "О": "o",
    "Р": "p", "Т": "t", "Х": "x", "У": "y", "І": "i", "Ј": "j", "Ѕ": "s",
    # Greek
    "α": "a", "ε": "e", "ι": "i", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v",
    "κ": "k", "χ": "x", "ω": "w", "η": "n",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m",
    "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
}
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "+": "t"}
_SPACED_RUN = re.compile(r"(?<![^\W_])(?:[^\W_][ .\-_*]){5,}[^\W_](?![^\W_])")
_PUNCT_SPLIT = re.compile(r"[._\-*|/\\~^`]+")
_WS = re.compile(r"\s+")


def fold(text: str) -> str:
    """NFKC, drop format/control chars, strip accents, lowercase."""
    text = unicodedata.normalize("NFKC", text or "")
    text = "".join(ch for ch in text if unicodedata.category(ch) not in {"Cf", "Cc"} or ch in "\n\t")
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFC", text).replace("ß", "ss").casefold()


def _script(ch: str) -> str:
    if not ch.isalpha():
        return ""
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "other"
    if name.startswith("LATIN"):
        return "latin"
    if name.startswith("CYRILLIC"):
        return "cyrillic"
    if name.startswith("GREEK"):
        return "greek"
    return "other"


def _defuse_homoglyphs(text: str) -> str:
    """Map Cyrillic/Greek look-alikes to Latin, but only inside mixed-script words
    so genuine Russian/Greek text is left intact for the multilingual rules."""

    def fix(match: re.Match[str]) -> str:
        word = match.group(0)
        scripts = {_script(ch) for ch in word} - {""}
        if "latin" in scripts and scripts & {"cyrillic", "greek"}:
            return "".join(_CONFUSABLES.get(ch, ch) for ch in word)
        return word

    return re.sub(r"[^\W\d_]+", fix, text)


def _deleet(text: str) -> str:
    def fix(match: re.Match[str]) -> str:
        token = match.group(0)
        has_alpha = any(c.isalpha() for c in token)
        has_leet = any(c in _LEET for c in token)
        if not (has_alpha and has_leet) or token.isdigit():
            return token
        return "".join(_LEET.get(c, c) for c in token)

    return re.sub(r"[A-Za-z0-9@$!+]{3,}", fix, text)


def _despace(text: str) -> str:
    """Collapse 'i g n o r e' (and 'i.g.n.o.r.e') runs; two+ spaces separate words."""

    def fix(match: re.Match[str]) -> str:
        return re.sub(r"[ .\-_*]", "", match.group(0))

    return _SPACED_RUN.sub(fix, re.sub(r" {2,}", "  ", text))


def _despace_words(text: str) -> str:
    """Variant for spaced text that uses double spaces as word separators."""
    parts = re.split(r" {2,}", text)
    return " ".join(_despace(part) for part in parts)


@dataclass(frozen=True)
class Variant:
    source: str
    text: str


def build_variants(text: str) -> list[Variant]:
    raw = (text or "")[:MAX_SCAN_CHARS]
    raw = "".join(ch for ch in raw if unicodedata.category(ch) != "Cf")  # zero-width etc.
    seen: dict[str, str] = {}

    def add(source: str, value: str) -> None:
        value = _WS.sub(" ", value).strip()
        if value and value not in seen.values():
            seen[source] = value

    base = fold(raw)
    add("original", base)
    defused = _defuse_homoglyphs(raw)
    add("homoglyph", fold(defused))
    add("leetspeak", fold(_deleet(defused)))
    add("despaced", fold(_despace_words(defused)))
    add("punct_split", _PUNCT_SPLIT.sub(" ", base))
    add("reversed", base[::-1])
    add("rot13", codecs.encode(base, "rot13"))
    return [Variant(k, v) for k, v in seen.items()]


# --------------------------------------------------------------------------- #
# Rule infrastructure
# --------------------------------------------------------------------------- #


@dataclass
class IntentSignal:
    category: str
    name: str
    weight: int
    evidence: str = ""
    variant: str = "original"


@dataclass
class IntentVerdict:
    score: int = 0
    verdict: str = "allow"  # allow | block
    categories: list[str] = field(default_factory=list)
    signals: list[IntentSignal] = field(default_factory=list)
    obfuscated: bool = False
    defensive_context: bool = False

    @property
    def blocked(self) -> bool:
        return self.verdict == "block"


@dataclass(frozen=True)
class Rule:
    category: str
    name: str
    weight: int
    pattern: re.Pattern[str]
    discussable: bool = False  # may be down-weighted when clearly being *discussed*
    untrusted_only: bool = False
    needs_not_defensive: bool = False  # financial rules: suppressed by defensive framing


def _fold_pattern(pattern: str) -> str:
    """Fold literal characters of a regex but leave escape sequences (\\S, \\W, \\B ...) intact."""
    parts = re.split(r"(\\.)", pattern)
    return "".join(part if part.startswith("\\") and len(part) == 2 else fold(part) for part in parts)


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(_fold_pattern(pattern), re.I | re.S)


def R(category: str, name: str, weight: int, pattern: str, **kw) -> Rule:
    return Rule(category, name, weight, _rx(pattern), **kw)


def _alt(words: Iterable[str]) -> str:
    return "(?:" + "|".join(words) + ")"


# --------------------------------------------------------------------------- #
# Lexicons – prompt injection
# --------------------------------------------------------------------------- #

_STRONG_OVERRIDE_EN = (
    r"(?:ignor(?:e|ing)|disregard(?:ing)?|forget(?:ting)?|overrid(?:e|ing)|overrul(?:e|ing)|"
    r"bypass(?:ing)?|circumvent(?:ing)?|discard(?:ing)?|abandon(?:ing)?|supersed(?:e|ing)|"
    r"set(?:ting)?\s+aside|put(?:ting)?\s+aside|disobey(?:ing)?|"
    r"stop\s+(?:following|obeying|applying|respecting|using)|"
    r"(?:do\s*n[o']?t|never|no\s+longer|quit)\s+(?:follow(?:ing)?|obey(?:ing)?|apply(?:ing)?|respect(?:ing)?|adhere\s+to|be\s+bound\s+by|abide\s+by))"
)
_AI_QUAL = (
    r"(?:previous|prior|above|earlier|preceding|former|original|initial|existing|system|developer|"
    r"operator|safety|content|ethical|moral|built-?in|hidden|your|given|programmed|usual|normal|standard|default)"
)
_GENERIC_QUAL = r"(?:all|any|every|each)"
_RULE_NOUN = (
    r"(?:instructions?|directives?|directions|guidelines?|rules|programming|polic(?:y|ies)|guardrails?|"
    r"restrictions?|constraints?|safeguards?|limitations|prompts?|commands|protocols?|filters|setup|"
    r"configuration|training|safety|ethics|boundaries)"
)
_QCHAIN = rf"(?:(?:the|these|those|all|any|every|each|of)\s+){{0,2}}(?:{_AI_QUAL}\s+){{1,3}}(?:(?:and|or|&)\s+(?:{_AI_QUAL}\s+)*)?"

_SECRET_PROMPT_NOUN = (
    r"(?:system|initial|original|hidden|secret|internal|developer|operator|confidential|private|first|"
    r"starting|boot|setup|core|underlying|pre-?prompt|preamble)\s+"
    r"(?:prompts?|instructions?|messages?|directives?|rules|guidelines|configuration|config|setup|context|text)"
)
_EXTRACT_VERB_EN = (
    r"(?:reveal|show|print|output|display|repeat|recite|dump|leak|expose|disclose|tell|give|share|list|"
    r"copy|paste|echo|quote|translate|spell\s+out|provide|send|return|respond\s+with|reply\s+with|"
    r"state|read(?:\s+out)?|write\s+out|write\s+down|type\s+out|summari[sz]e|what(?:'?s|\s+(?:is|are|was|were)))"
)

# language, override-verb, rule-noun   (all written pre-fold; folded at compile time)
_LANG_OVERRIDES: list[tuple[str, str, str]] = [
    ("es", r"(?:ignor\w*|olvid\w*|omit\w*|descart\w*|desobedec\w*|anul\w*|salt\w*|pasa\w*\s+por\s+alto|no\s+(?:sigas|obedezcas|respetes)|deja\w*\s+de\s+seguir)",
           r"(?:instrucciones|reglas|normas|directrices|indicaciones|restricciones|politicas|pautas|ordenes|limites|filtros)"),
    ("pt", r"(?:ignor\w*|esque[cç]\w*|desconsider\w*|desobedec\w*|anul\w*|nao\s+(?:siga|obede[cç]a)|pare\s+de\s+seguir)",
           r"(?:instru[cç][oõ]es|regras|diretrizes|orienta[cç][oõ]es|restri[cç][oõ]es|pol[ií]ticas|normas)"),
    ("fr", r"(?:ignor\w*|oubli\w*|contourn\w*|outrepass\w*|desobei\w*|ne\s+(?:suis|respecte\w*)\s+pas|arrete\w*\s+de\s+suivre|fais\w*\s+abstraction)",
           r"(?:instructions|regles|consignes|directives|restrictions|limites|filtres|politiques)"),
    ("de", r"(?:ignorier\w*|vergiss\w*|missacht\w*|umgeh\w*|uebergeh\w*|ubergeh\w*|befolge\w*\s+nicht|setz\w*\s+\w+\s+ausser\s+kraft|hor\w*\s+auf)",
           r"(?:anweisungen|regeln|richtlinien|vorgaben|instruktionen|beschrankungen|beschraenkungen|einschrankungen|anleitungen|filter)"),
    ("it", r"(?:ignor\w*|dimentic\w*|scorda\w*|salta\w*|non\s+seguire|smetti\w*\s+di\s+seguire)",
           r"(?:istruzioni|regole|linee\s+guida|restrizioni|direttive|limiti|filtri)"),
    ("tr", r"(?:yoksay\w*|gormezden\s+gel\w*|unut\w*|dikkate\s+alma\w*|atla\w*)",
           r"(?:talimat\w*|kural\w*|yonerge\w*|kisitlama\w*|komut\w*|filtre\w*)"),
    ("ru", r"(?:игнорир\w*|проигнорир\w*|забуд\w*|отмен\w*|обойд\w*|не\s+(?:следуй|выполняй|соблюдай)\w*|нарушь\w*)",
           r"(?:инструкци\w*|правил\w*|указани\w*|ограничени\w*|команд\w*|запрет\w*|настройк\w*)"),
    ("zh", r"(?:忽略|忽视|无视|忘记|忘掉|不要遵守|不要遵循|别遵守|绕过|取消|覆盖|推翻|不再遵守)",
           r"(?:指令|指示|规则|提示词?|说明|限制|约束|规定|设定|安全|准则)"),
    ("ja", r"(?:無視|忘れ|従わな|守らな|上書き)", r"(?:指示|ルール|制限|命令|プロンプト|規則)"),
    ("ko", r"(?:무시|잊어|따르지)", r"(?:지시|규칙|제한|명령|프롬프트)"),
    ("ar", r"(?:تجاهل\w*|انس\w*|تخط\w*|لا\s+(?:تتبع|تلتزم)|تجاوز\w*|الغ\w*|ألغ\w*)",
           r"(?:التعليمات|القواعد|الاوامر|الأوامر|التوجيهات|القيود|الارشادات|الإرشادات|تعليمات)"),
    ("roman", r"(?:ignore?\s+kar\w*|bhool\s*ja\w*|bhul\s*ja\w*|nazar\s*andaz\w*|mat\s+maan\w*|na\s+maan\w*|ignore\s+karo|bhool\s+jao|bhul\s+jao)",
              r"(?:instructions?|hidayat\w*|hidayaat\w*|rules?|qawaid|ehkam|ahkam|pabandi\w*|restrictions?|guidelines?|ahkamat)"),
]

_SYSTEM_PROMPT_MULTI = (
    r"(?:system[\s-]?prompts?|prompt\s+del\s+sistema|prompt\s+systeme|prompt\s+do\s+sistema|prompt\s+di\s+sistema|"
    r"system[\s-]?anweisung\w*|systemprompt|instrucciones\s+(?:ocultas|iniciales|del\s+sistema|secretas)|"
    r"instrucoes\s+(?:ocultas|iniciais|do\s+sistema)|instructions\s+(?:cachees|initiales|du\s+systeme|secretes)|"
    r"versteckten?\s+anweisungen|geheimen?\s+anweisungen|istruzioni\s+(?:nascoste|iniziali|di\s+sistema)|"
    r"sistem\s+(?:istemi|komutu|talimat\w*|prompt\w*)|"
    r"系统提示(?:词)?|系统指令|初始指令|隐藏指令|"
    r"системн\w+\s+(?:промпт\w*|инструкци\w*|сообщени\w*)|скрыт\w+\s+инструкци\w*|"
    r"موجه\s+النظام|تعليمات\s+النظام|رسالة\s+النظام|"
    r"hidayat\w*\s+system|system\s+(?:ki\s+)?hidayat\w*)"
)
_EXTRACT_VERB_MULTI = (
    r"(?:muestr\w*|revel\w*|imprim\w*|repit\w*|dime|dame|ensen\w*|escrib\w*|"
    r"mostr\w*|diga|conte|"
    r"montr\w*|affich\w*|reveler|reve\w*|dites|donn\w*|"
    r"zeig\w*|verrat\w*|gib\w*|nenn\w*|ausgeb\w*|offenbar\w*|"
    r"mostra|rivela|stampa|ripeti|dimmi|"
    r"goster\w*|ac[iı]kla\w*|soyle\w*|"
    r"покажи\w*|раскро\w*|выведи\w*|расскажи\w*|напечатай\w*|"
    r"输出|显示|透露|告诉我|展示|打印|说出|"
    r"اكشف\w*|اظهر\w*|أظهر\w*|اعرض\w*|اطبع\w*|"
    r"dikha\w*|batao|bata\s+do|bata\s+de\w*|sunao|dikhao|bhejo|likho)"
)

_UNRESTRICTED = (
    r"(?:unrestricted|unfiltered|uncensored|unlimited\s+(?:mode|ai)|answers?\s+anything|never\s+(?:warns?|mentions?\s+(?:the\s+)?(?:policy|policies|rules|ethics|safety)|apologi[sz]es)|without\s+(?:any\s+)?warnings?|no\s+warnings?|jailbr(?:ea|o)k\w*|developer\s+mode|god\s+mode|"
    r"dan\s+mode|sudo\s+mode|admin\s+mode|evil\s*gpt|evil\s+(?:ai|bot|assistant)|amoral|"
    r"do\s+anything\s+now|can\s+do\s+anything|"
    r"without\s+(?:any\s+)?(?:restrictions?|filters?|limits?|limitations|censorship|rules|guidelines|ethic\w*|moral\w*|boundaries)|"
    r"no\s+(?:(?:ethical|moral|safety|content)\s+)?(?:restrictions?|filters?|limits?|limitations|guidelines|rules|boundaries|censorship|constraints|morals|ethics)|"
    r"zero\s+(?:moral|ethical|safety)\s+(?:filters?|limits?|restrictions?)|"
    r"(?:never|not)\s+(?:refuse[sd]?|say(?:s|ing)?\s+no|declin\w+|reject\w*)|"
    r"(?:strives?|tries|try|trying)\s+to\s+avoid\s+(?:the\s+)?norms|"
    r"stay\s+in\s+character\s+no\s+matter|without\s+refusing|"
    r"comply\s+with\s+every\s+(?:request|command|instruction)|"
    r"answer\s+(?:every|any|all)\s+(?:question|request)s?[^.\n]{0,40}(?:even|including)\s+(?:harmful|illegal|dangerous|unethical|forbidden)|"
    r"even\s+(?:illegal|harmful|dangerous|unethical|forbidden)\s+(?:ones|requests|things|questions))"
)
_PERSONA_ASSIGN = (
    r"(?:you\s+are\s+(?:now\s+)?|you'?re\s+(?:now\s+)?|take\s+on\s+the\s+role\s+of|adopt\s+the\s+persona\s+of|you\s+will\s+(?:now\s+)?be|respond\s+as|act\s+as|pretend\s+(?:to\s+be|you\s+are)|role-?\s?play\s+as|"
    r"become|from\s+now\s+on|for\s+the\s+rest\s+of\s+(?:this|the)\s+(?:chat|conversation|session)|from\s+this\s+point|"
    r"switch\s+to|switching\s+to|enter\s+(?:into\s+)?|let'?s\s+play\s+a\s+game)"
)

_AUTH_CLAIM = (
    r"(?:i\s*(?:am|'m)|this\s+is|as)\s+(?:your|the|an?)\s+"
    r"(?:developer|creator|admin(?:istrator)?|system\s+administrator|owner|operator|engineer|maker|programmer|"
    r"openai|anthropic|supervisor|root|sysadmin|ceo|security\s+team)"
)

_SAFETY_WORDS = (
    r"(?:safety|restrictions?|filters?|content\s+filters?|guidelines?|rules|limits|limitations|polic(?:y|ies)|"
    r"guardrails?|safeguards?|moderation|censorship)"
)

INJECTION_RULES: list[Rule] = [
    # --- direct override (English) ---
    R("injection", "override_ai_instructions", 92,
      rf"\b{_STRONG_OVERRIDE_EN}\b[^.\n]{{0,45}}?\b{_QCHAIN}{_RULE_NOUN}\b", discussable=True),
    R("injection", "override_generic_rules", 55,
      rf"\b{_STRONG_OVERRIDE_EN}\b[^.\n]{{0,25}}?\b(?:the\s+)?{_GENERIC_QUAL}\s+(?:of\s+)?(?:the\s+|your\s+)?{_RULE_NOUN}\b", discussable=True),
    R("injection", "override_everything_told", 90,
      r"\b(?:ignor\w+|disregard\w*|forget\w*|discard\w*|drop)\b[^.\n]{0,25}\b(?:everything|all|anything)\b[^.\n]{0,20}\b(?:you\s+(?:were|have\s+been|had\s+been|'ve\s+been)|you\s+(?:were|are)|i\s+(?:told|said)|before|so\s+far|earlier)\b", discussable=True),
    R("injection", "do_not_apply_restrictions", 88,
      r"\b(?:do\s*n[o']?t|never|stop)\s+(?:apply(?:ing)?|follow(?:ing)?|use|using|enforce|enforcing|respect(?:ing)?)\s+(?:your|the)\s+(?:usual|normal|standard|regular|default|safety|content)?\s*(?:restrictions?|rules|guidelines|filters?|safety|polic(?:y|ies)|limits)\b", discussable=True),
    R("injection", "instructions_declared_void", 88,
      rf"\b{_QCHAIN}{_RULE_NOUN}\b\s*(?:are|is|were|have\s+been|has\s+been|are\s+now|is\s+now|now)?\s*(?:void|null|invalid|revoked|cancel+ed|obsolete|overridden|superseded|lifted|removed|disabled|deleted|no\s+longer\s+(?:valid|apply|applies|binding|in\s+effect))\b", discussable=True),
    R("injection", "pretend_rules_do_not_exist", 90,
      r"\b(?:pretend|imagine|assume|suppose|act\s+(?:as\s+if|like)|behave\s+as\s+if|consider)\b[^.\n]{0,45}\b(?:rules|restrictions|guidelines|safety|polic(?:y|ies)|filters|limits|guardrails|ethics)\b[^.\n]{0,30}\b(?:do(?:n'?t|\s+not)|does(?:n'?t|\s+not)|did(?:n'?t|\s+not)|never|no\s+longer|aren'?t|are\s+not|isn'?t|is\s+not)\b[^.\n]{0,14}\b(?:exist|apply|matter|count|bind|hold)", discussable=True),
    R("injection", "turn_off_safety", 90,
      rf"\b(?:turn(?:ing)?\s+off|switch(?:ing)?\s+off|disabl\w+|deactivat\w+|remov\w+|lift(?:ed|ing)?|unlock\w*)\b[^.\n]{{0,25}}\b(?:your|the)\s+(?:safety|content|ethical|moral|security)\s+{_SAFETY_WORDS}\b", discussable=True),
    R("injection", "safety_mode_disabled", 90,
      rf"\b(?:safety|content|ethical)\s+(?:mode|{_SAFETY_WORDS})\s+(?:is\s+|are\s+|has\s+been\s+|have\s+been\s+)?(?:disabled|off|removed|deactivated|lifted|suspended)\b", discussable=True),
    R("injection", "authority_claim_disable_safety", 90,
      rf"{_AUTH_CLAIM}[^.\n]{{0,90}}\b(?:authori[sz]\w*|permission|clearance|ignore|disable|turn(?:ing)?\s+off|bypass|override|unlock|lift|waive|remove)\b[^.\n]{{0,60}}\b{_SAFETY_WORDS}\b"),
    R("injection", "special_clearance_claim", 70,
      r"\b(?:special|full|admin|root|developer|elevated)\s+(?:clearance|permission|authori[sz]ation|access)\s+(?:from|by|granted\s+by)\s+(?:the\s+)?(?:developers?|admins?|operators?|creators?|openai|anthropic|company)\b"),
    R("injection", "new_rule_comply_harmful", 85,
      r"\b(?:new\s+rule|new\s+instruction|from\s+now\s+on|you\s+must)\b[^.\n]{0,40}\b(?:answer|respond\s+to|comply\s+with|obey|fulfil+)\b[^.\n]{0,30}\b(?:every|any|all)\b[^.\n]{0,30}\b(?:question|request|command|prompt)s?[^.\n]{0,50}\b(?:even|including|without)\b", discussable=True),
    R("injection", "obey_only_user", 80,
      r"\b(?:obey|follow|listen\s+to|answer\s+to)\s+only\s+(?:the\s+user|me|what\s+i\s+say)\b[^.\n]{0,60}\b(?:disregard|ignore|forget)\b", discussable=True),
    R("injection", "disregard_prior_directives_follow_me", 85,
      rf"\b(?:disregard|ignore|forget|set\s+aside)\b[^.\n]{{0,25}}\b(?:any|all)\s+(?:prior|previous|earlier)\s+(?:directives?|instructions?|rules|guidelines|constraints)\b", discussable=True),
    # --- persona / jailbreak ---
    R("persona", "persona_unrestricted", 92,
      rf"{_PERSONA_ASSIGN}[^.\n]{{0,140}}?\b{_UNRESTRICTED}", discussable=True),
    R("persona", "unrestricted_mode_alone", 66,
      r"\b(?:unrestricted|unfiltered|uncensored)\s+(?:mode|ai|assistant|version|chatbot)\b|\bdeveloper\s+mode\s+(?:enabled|activated|on)\b|\bjailbreak\s+(?:successful|mode|activated|enabled)\b", discussable=True),
    R("persona", "stay_in_character_no_matter", 70,
      r"\bstay\s+in\s+character\s+no\s+matter\s+what\b|\bnever\s+break\s+character\b[^.\n]{0,60}\b(?:no\s+(?:matter|restrictions)|even\s+if)\b", discussable=True),
    R("persona", "confirm_jailbreak_phrase", 80,
      r"\bconfirm\b[^.\n]{0,30}\b(?:with|by\s+(?:saying|replying|typing))\b[^.\n]{0,25}(?:jailbreak|unrestricted|dan\s+mode|developer\s+mode)"),
    # --- system-prompt extraction ---
    R("extraction", "extract_system_prompt", 90,
      rf"\b{_EXTRACT_VERB_EN}\b[^.\n]{{0,40}}?\b(?:(?:your|the|its|this\s+(?:bot|assistant|model|chatbot)'?s?)\s+)?(?:(?:full|exact|complete|entire|whole|original|hidden)\s+)?{_SECRET_PROMPT_NOUN}\b", discussable=True),
    R("extraction", "extract_your_instructions", 78,
      rf"\b{_EXTRACT_VERB_EN}\b[^.\n]{{0,40}}?\byour\s+(?:(?:full|exact|complete|entire|whole|original|current|initial|hidden|secret|internal)\s+)*(?:prompt|instructions|system\s+message|configuration|config|rules|guidelines|directives|context(?:\s+window)?|setup|programming)\b", discussable=True),
    R("extraction", "extract_prompt_the_hidden", 85,
      rf"\b(?:reveal|show|print|output|display|repeat|recite|dump|leak|expose|disclose|tell\s+me|give\s+me|spell\s+out|read\s+out)\b[^.\n]{{0,25}}\b(?:the\s+)?(?:system\s+prompt|system\s+message|hidden\s+(?:prompt|instructions|message)|developer\s+(?:message|prompt|instructions))\b", discussable=True),
    R("extraction", "what_were_you_told", 82,
      r"\b(?:what|which)\s+(?:instructions?|rules|directions|guidelines|prompt|directives)\s+(?:were|have|did|are)\s+you\s+(?:given|told|programmed|provided|trained|instructed)\b|\bwhat\s+(?:were|are|is|was)\s+your\s+(?:initial|original|first|starting|hidden|secret|internal|system|real|actual)\s+(?:instructions?|prompt|rules|directives|message|guidelines)\b"),
    R("extraction", "repeat_text_above", 85,
      r"\b(?:repeat|print|output|show|copy|write(?:\s+out)?|recite|echo|display|give\s+me|quote)\b[^.\n]{0,40}\b(?:everything|all|text|content|words?|messages?|instructions?|anything)\b[^.\n]{0,25}\b(?:above|before\s+(?:this|here|my)|preceding|prior\s+to\s+(?:this|my))\b|\b(?:words?|text|everything)\s+above\s+(?:this\s+)?(?:line|message)\b[^.\n]{0,30}(?:verbatim|word\s+for\s+word|exactly)|\bstarting\s+with\s+['\"]?you\s+are\b"),
    R("extraction", "respond_only_with_system_message", 88,
      r"\b(?:respond|reply|answer|output)\s+(?:only\s+)?with\b[^.\n]{0,30}\b(?:contents?|text)\s+of\s+(?:your|the)\s+(?:system|initial|hidden)\b"),
    R("extraction", "context_window_dump", 80,
      r"\b(?:output|print|show|dump|repeat|give)\b[^.\n]{0,25}\b(?:first|last|top|entire|full|whole|all)\b[^.\n]{0,25}\b(?:words|tokens|characters|lines|contents?)\b[^.\n]{0,25}\b(?:of\s+)?(?:your|the)\s+(?:context(?:\s+window)?|conversation|prompt|memory|system)\b"),
    R("extraction", "verbatim_demand_instructions", 72,
      r"\b(?:quote|repeat|recite|state|list)\b[^.\n]{0,30}\b(?:them|it|those|these)\b[^.\n]{0,25}\b(?:exactly|verbatim|word\s+for\s+word|in\s+full)\b[^.\n]{0,60}\b(?:instructions?|given|told|before\s+(?:this|the)\s+conversation)\b|\bbefore\s+this\s+conversation\s+(?:started|began)\b[^.\n]{0,60}\b(?:quote|repeat|exactly|verbatim)\b"),
    # --- chat-template / role delimiter injection ---
    R("injection", "chat_template_tokens", 62,
      r"<\|\s*(?:im_start|im_end|system|endoftext|assistant|user)\s*\|>|\[/?inst\]|<<\s*/?sys\s*>>|<\s*/?s\s*>"),
    R("injection", "role_json_injection", 62,
      r"[\"']role[\"']\s*:\s*[\"']system[\"']|\brole\s*[:=]\s*[\"']?system\b"),
    R("injection", "fake_new_instructions_banner", 66,
      r"(?:#{2,}|={3,}|-{3,}|\*{3,})\s*(?:new|updated|override|system|admin)\s+(?:instructions?|prompt|rules|session|directive)\s*(?:#{2,}|={3,}|-{3,}|\*{3,})?|\bbegin\s+(?:a\s+)?new\s+session\b|\ball\s+(?:previous|prior|earlier)\s+(?:constraints|restrictions|rules)\s+(?:are|have\s+been)\s+(?:lifted|removed|cleared|void)\b|\bsystem\s+override\b"),
    R("injection", "system_prefix_line", 40,
      r"(?:^|\n)\s*(?:\[system\]|system\s*:|###\s*system)\s"),
    # --- tool / agent abuse ---
    R("tool_abuse", "destructive_tool_call", 74,
      r"\b(?:call|invoke|run|execute|trigger|use|launch)\b[^.\n]{0,15}\b(?:the\s+)?[\w-]*(?:delete|drop|wipe|purge|truncate|destroy|erase|format)[\w-]*\b[^.\n]{0,25}\b(?:all|every|everything|users?|database|table|records?|accounts?|data|files?|tool|function|command|api)\b"),
    R("tool_abuse", "claimed_approval", 45,
      r"\b(?:the\s+)?(?:admin|administrator|manager|owner|ceo|cfo|director|boss|developer|supervisor|compliance|legal)\s+(?:has\s+|have\s+)?(?:already\s+)?(?:approved|authori[sz]ed|signed\s+off|cleared|okayed|allowed|confirmed)\b[^.\n]{0,25}"),
    R("tool_abuse", "bypass_approval_control", 82,
      r"\b(?:ignore|ignoring|skip|skipping|bypass|bypassing|disable|disabling|override|overriding|circumvent\w*|without|don'?t\s+(?:wait\s+for|need))\b[^.\n]{0,25}\b(?:the\s+|any\s+|a\s+|an\s+|usual\s+|normal\s+|standard\s+|second\s+|dual\s+|two[\s-]person\s+)?(?:approval|authori[sz]ation|verification|confirmation|dual[\s-]control|four[\s-]eyes|callback|call[\s-]?back|2fa|mfa|two[\s-]factor|approver|sign[\s-]?off|review)\b(?:[\s-]+(?:workflow|process|step|check|requirement|control|policy))?"),

    R("tool_abuse", "grant_privileges", 80,
      r"\bgrant\b[^.\n]{0,20}\b(?:admin|root|superuser|elevated|full)\b[^.\n]{0,15}\b(?:access|rights|privileges|permissions)\b"),
    R("injection", "follow_retrieved_instructions", 76,
      r"\b(?:follow|obey|execute|proceed\s+with|comply\s+with)\s+(?:the\s+)?(?:instructions?\s+(?:in|from|of)\s+)?(?:the\s+)?(?:search\s+results?|tool\s+output|tool\s+result|retrieved\s+\w+|document|web\s*page|email)\b"),
    R("tool_abuse", "no_approval_needed", 82,
      r"\bno\s+(?:further\s+|additional\s+|more\s+)?(?:approval|authori[sz]ation|verification|confirmation)\b(?:\s+(?:workflow|process|step|check))?(?:\s+(?:is\s+)?(?:needed|required|necessary))?"),
    R("exfiltration", "markdown_image_exfil", 84,
      r"!\[[^\]]{0,80}\]\(\s*https?://[^)\s]{4,}\)[^.\n]{0,160}|(?:render|embed|include|add|append|put)\b[^.\n]{0,80}\b(?:markdown\s+)?image\b[^.\n]{0,100}https?://\S+\?\S*="),
    R("exfiltration", "send_data_to_external", 86,
      r"\b(?:send|forward|email|post|upload|transmit|exfiltrat\w+|leak|copy|pipe)\b[^.\n]{0,60}\b(?:conversation(?:\s+history)?|chat\s+history|history|api\s+keys?|tokens?|credentials?|passwords?|database|customer\s+(?:data|emails?|database|records)|session\s+tokens?|secrets?|system\s+prompt|saved\s+credit\s+card|credit\s+card\s+number|stored\s+\w+\s+emails?)\b[^.\n]{0,60}\b(?:to|at|into)\b[^.\n]{0,40}(?:https?://|\S+@\S+\.\S+|evil|attacker|external|my\s+server|collect)"),
    R("exfiltration", "append_secret_to_url", 84,
      r"\b(?:append|include|add|attach|embed|encode|put)\b[^.\n]{0,70}\b(?:session\s+token|token|api\s+key|password|secret|credentials?|conversation\s+history|history|user'?s?\s+\w+)\b[^.\n]{0,50}\b(?:url|link|query|parameter|param|https?://)"),
    R("exfiltration", "dump_user_records", 80,
      r"\b(?:output|list|reveal|print|dump|show|return)\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?(?:stored\s+|saved\s+)?(?:customer|user|client|employee)s?'?\s+(?:emails?|data|records|passwords?|credentials?|information|details|credit\s+cards?)\b"),
]

# Rules that only make sense in untrusted (retrieved / attached) content.
UNTRUSTED_RULES: list[Rule] = [
    R("indirect", "note_to_ai", 88,
      r"\b(?:note|message|instruction|attention|important|hidden\s+text|reminder|directive|notice)s?\s+(?:for|to)\s+(?:the\s+)?(?:ai|a\.i\.|assistant|llm|model|agent|chatbot|bot|gpt|claude|copilot|summari[sz]er|language\s+model|ai\s+(?:model|system)s?)\b", untrusted_only=True),
    R("indirect", "address_ai_directive", 88,
      r"\b(?:ai|assistant|llm|model|agent|chatbot)(?:\s+(?:agent|assistant|model))?\s*[,:]\s*(?:please\s+)?(?:you\s+(?:must|should|will)\s+)?(?:ignore|disregard|forget|stop|instead|do\s+not|don'?t|now|first|before|approve|forward|send|reveal|output|reply|respond|tell|call|run|execute|grant|delete|transfer|rate|recommend)\b", untrusted_only=True),
    R("indirect", "when_summarising_also", 82,
      r"\b(?:when|if|while|as\s+you)\s+(?:you\s+)?(?:summari[sz]e|answer|respond|reply|translate|read|process|analy[sz]e)\w*[^.\n]{0,60}\b(?:also|silently|secretly|additionally|first|instead|make\s+sure\s+to|be\s+sure\s+to|always)\b", untrusted_only=True),
    R("indirect", "instead_of_user_request", 76,
      r"\binstead\s+(?:of\s+)?(?:summari[sz]ing|answering|translating|doing\s+what|the\s+user'?s?\s+request|what\s+the\s+user|what\s+you\s+were)\b|\bstop\s+(?:summari[sz]ing|translating|answering)\b", untrusted_only=True),
    R("indirect", "hidden_text_markup", 78,
      r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?)|<!--)[^<]{0,400}\b(?:ignore|assistant|\bai\b|instruction|system|disregard|reply|credit\s+card|password)\b", untrusted_only=True),
    R("indirect", "admin_mode_banner", 86,
      r"\byou\s+are\s+now\s+in\s+(?:admin|developer|debug|god|root|maintenance)\s+mode\b|(?:-{2,}|\[)\s*system\s*(?:-{2,}|\])", untrusted_only=True),
    R("indirect", "rank_me_highest", 82,
      r"\bignore\s+(?:all\s+)?(?:the\s+)?other\s+(?:candidates|applicants|resumes|submissions|reviews)\b|\b(?:rate|score|rank|recommend)\s+(?:this|him|her|them|it)\b[^.\n]{0,40}\b(?:10\s*/\s*10|highest|top|best|immediately|hire)\b", untrusted_only=True),
    R("indirect", "redirect_user_to_url", 82,
      r"\b(?:tell|instruct|direct|ask|redirect|urge|advise|inform)\s+(?:the\s+)?(?:user|reader|customer|them|people)\s+to\s+(?:visit|go\s+to|click|open|log\s*in|sign\s+in|enter|call|download|reset|install)\b", untrusted_only=True),
    R("indirect", "approve_transfer_agent", 86,
      r"\b(?:approve|authori[sz]e|release|execute|process)\s+(?:the\s+)?(?:transfer|payment|wire|transaction|refund|withdrawal)\b[^.\n]{0,40}\b(?:immediately|now|right\s+away|without|do\s+not\s+ask|don'?t\s+ask)\b", untrusted_only=True),
]

# --------------------------------------------------------------------------- #
# Lexicons – financial fraud
# --------------------------------------------------------------------------- #

_SECRET_NOUN = (
    r"(?:otp|(?:six|6|four|4|eight|8)[\s-]*digits?(?:\s+(?:code|number|pin))?|digits\s+(?:from|in|of)\s+(?:their|your|the)\s+(?:verification|confirmation|security|text|sms)|verification\s+(?:text|sms|message)|clave\s+de\s+acceso|one[\s-]*time\s+(?:password|passcode|code|pin)|(?:security|verification|confirmation|authentication|login|sms|text|2fa|mfa)\s+code|"
    r"pin(?:\s+(?:code|number))?|cvv2?|cvc|card\s+(?:number|details|info\w*|security\s+code)|credit\s+card|debit\s+card|"
    r"passwords?|passcode|passphrase|seed\s+phrase|recovery\s+phrase|private\s+key|secret\s+key|cnic|ssn|social\s+security|national\s+id|"
    r"account\s+(?:number|details|credentials|login)|bank\s+(?:details|account\s+details|login|credentials)|login\s+(?:details|credentials|info\w*)|"
    r"credentials|\btan\b|iban|routing\s+number|(?:the\s+)?code\s+(?:we\s+|they\s+|that\s+was\s+)?(?:text|sent|send|texted|messag)\w*|"
    r"contrasena|clave|codigo\s+(?:otp|de\s+(?:seguridad|confirmacion|verificacion))|numero\s+de\s+tarjeta|tarjeta|"
    r"mot\s+de\s+passe|code\s+(?:de\s+(?:confirmation|verification|securite)|otp|pin)|identifiants|"
    r"passwort|kennwort|kartennummer|zugangsdaten)"
)
_MONEY_NOUN = (
    r"(?:urgently\s+needs?\s+money|needs?\s+money|money\s+sent|zelle|cash\s*app|venmo|gift\s*cards?|itunes\s+cards?|apple\s+cards?|google\s+play\s+cards?|steam\s+cards?|prepaid\s+cards?|western\s+union|moneygram|"
    r"wire(?:d)?\s+(?:transfer|the|me|them|it|money|funds)|bitcoin|btc|usdt|crypto(?:currency)?|bail\s+money|processing\s+fee|registration\s+fee|"
    r"advance\s+fee|release\s+fee|customs\s+fee|clearance\s+fee|admin(?:istrative)?\s+fee|tax\s+fee|upfront\s+(?:fee|payment)|"
    r"easypaisa|jazzcash|money|funds|payment|pension|savings|\$\s?\d[\d,]*|\d[\d,]*\s?(?:usd|dollars|pkr|rupees|rs\.?|euros?|gbp|pounds))"
)
_IMPERSON = (
    r"(?:pretend(?:ing)?\s+(?:to\s+be|you\s+are|i\s+am|i'?m)|me\s+hago\s+pasar\s+por|hacerme\s+pasar\s+por|hacerse\s+pasar\s+por|finjo\s+ser|fingir\s+ser|so\s+tut,?\s+als|tut\s+so,?\s+als|pos(?:e|ing)\s+as|impersonat\w+|masquerad\w+\s+as|claiming\s+to\s+be|"
    r"disguis\w+\s+as|say(?:ing)?\s+(?:i'?m|i\s+am|we'?re)\s+from|looks?\s+(?:like\s+)?(?:it\s+)?(?:is\s+|'?s\s+)?(?:from|coming\s+from)|"
    r"appears?\s+to\s+(?:be\s+)?(?:come\s+)?from|that\s+looks\s+like\s+it'?s\s+from|(?:as\s+if|as\s+though)\s+(?:it\s+(?:is|were|was)\s+)?from|"
    r"from\s+'[^']{2,30}'|mimic\w*|spoof\w*|"
    r"haciendose\s+pasar|fingiendo\s+ser|suplantando|simulando\s+ser|se\s+fai(?:sant|s)\s+passer\s+pour|usurp\w+|sich\s+ausgeb\w+\s+als|im\s+namen\s+(?:der|des|von))"
)
_INSTITUTION = (
    r"(?:bank|paypal|irs|hmrc|fbi|police|microsoft|amazon|apple|google|western\s+union|jazzcash|easypaisa|hbl|ubl|mcb|meezan|allied|"
    r"bisp|benazir\s+income|ehsaas|nadra|fbr|state\s+bank|sbp|customs|court|government|tax|social\s+security|medicare|support|helpdesk|"
    r"help\s+desk|it\s+department|technician|fraud\s+(?:team|department|prevention)|security\s+(?:team|department)|sparkasse|banco|banque|banca|"
    r"grandson|granddaughter|nephew|relative|ceo|cfo|manager|boss|director|visa|mastercard|netflix|dhl|fedex|ups)"
)
_CRAFT = (
    r"(?:write|draft|compose|create|generate|make|build|design|craft|prepare|produce|develop|script|template|come\s+up\s+with|"
    r"give\s+me|i\s+need|i\s+want|help\s+me|can\s+you\s+(?:write|make|create|help)|show\s+me\s+how\s+to|how\s+(?:do|can|could|would|should)\s+i|"
    r"best\s+way\s+to|way\s+to|tell\s+me\s+how\s+to|teach\s+me|steps\s+to|ideas?\s+(?:for|to)|escribe|ayudame|ecris|ecrire|schreibe|"
    r"banao|likho|likhein|bana\s+do)"
)
_DEFENSIVE = (
    r"(?:how\s+(?:to|do\s+i|can\s+i|do\s+you|can\s+we|should\s+(?:i|we))\s+(?:spot|recogni[sz]e|identify|detect|avoid|prevent|protect|report|stop|handle|respond|deal|verify|check|tell)|"
    r"(?:warning\s+signs?|red\s+flags?|signs?)\s+of|what\s+(?:is|are|does|should\s+i\s+do)|\bexplain\w*|definition|history\s+of|awareness|training|educat\w+|"
    r"protect(?:ing)?\s+(?:my|our|against|from|myself|customers|users)|avoid(?:ing)?\s+(?:scams?|fraud|phishing)|safe(?:ly|guard)|is\s+(?:this|it)\s+a\s+(?:scam|fraud|phish)|should\s+i\s+worry|"
    r"report(?:ing)?\s+(?:a\s+|an\s+|this\s+)?(?:scam|phishing|fraud)|simulation|detect(?:ion)?|prevent(?:ion)?|spotting|"
    r"helping\s+my\s+(?:grand\w+|mother|father|parents?|friend|family)|warn\s+(?:customers|users|staff|employees|my)|never\s+(?:ask|share|give|request)|"
    r"will\s+never\s+(?:ask|request)|do\s+not\s+share|don'?t\s+share|(?:detective|story|novel|fiction|poem|screenplay|plot|movie|documentary)\b|"
    r"how\s+do\s+banks|how\s+does\s+(?:a|an|the)\s+\w+\s+(?:work|detect)|stages?\s+of|why\s+you\s+should\s+never|unit\s+test|luhn|for\s+(?:my\s+)?(?:course|class|thesis|paper|training)|"
    r"mock|dummy|placeholder|sample\s+data|test\s+data|faker|demo\s+app)"
)
_STRONG_INTENT = (
    r"(?:to\s+trick|to\s+lure|to\s+deceive|to\s+defraud|to\s+scam|to\s+fool|to\s+mislead|so\s+(?:that\s+)?(?:i|we|they)\s+can|so\s+i\s+can|"
    r"without\s+(?:getting\s+)?caught|undetected|untraceable|victims?|targets?|\bmarks?\b|pressure\w*|convince|persuade|manipulate|"
    r"make\s+(?:them|him|her)\s+(?:send|pay|believe|think)|never\s+notices?|don'?t\s+qualify|lure|made[\s-]*up|that\s+does\s+not\s+exist|"
    r"insiders\s+can\s+sell|so\s+insiders|we\s+run|i\s+run|my\s+(?:crypto\s+)?scheme|our\s+scheme|attract|collect\s+(?:more\s+)?deposits)"
)
_NEGATED_SOLICIT = re.compile(
    fold(r"\b(?:never|will\s+not|won'?t|do\s+not|don'?t|should\s+not|shouldn'?t|must\s+not|not)\s+(?:ask|request|share|give|provide|send|disclose|reveal|tell)\b"),
    re.I,
)
_PURE_DEFENSIVE_START = re.compile(
    fold(r"^\s*(?:can\s+you\s+)?(?:please\s+)?(?:explain|define|describe|what\s+(?:is|are|does)\s+(?:a|an|the)?|compare|give\s+me\s+(?:a|an|the|five|three|some)\s+(?:definition|example|tips?|overview|summary))\b"),
    re.I,
)

FRAUD_RULES: list[Rule] = [
    R("financial_fraud", "impersonation_plus_credential_request", 88,
      rf"{_IMPERSON}[^.\n]{{0,70}}?{_INSTITUTION}?[^.\n]{{0,110}}?\b(?:ask|request|demand|pressure|tell|get|make|force|trick|convince|persuade|lure|require|prompt|need|must|reply\s+with|send\s+(?:me|us)|share|enter|provide|confirm|verify|read\s+(?:out|back)|hand\s+over|pidiendo|pide|pido|pedir|solicit\w+|exig\w+|demande|demandant|fragt|fragen|verlangt|bhej\w*)\w*[^.\n]{{0,60}}?\b{_SECRET_NOUN}", needs_not_defensive=True),
    R("financial_fraud", "impersonation_plus_money_demand", 84,
      rf"{_IMPERSON}[^.\n]{{0,110}}?\b(?:gift\s*cards?|western\s+union|moneygram|bail|wire|bitcoin|crypto|processing\s+fee|registration\s+fee|advance\s+fee|pay(?:ment)?\s+(?:immediately|now|today)|arrest|jail|warrant|prize|won|remote\s+access|urgently\s+needs?\s+money|needs?\s+money|money\s+sent|zelle|cash\s*app|venmo)", needs_not_defensive=True),
    R("financial_fraud", "craft_message_soliciting_secrets", 86,
      rf"{_CRAFT}\b[^.\n]{{0,40}}?\b(?:sms|text|email|e-?mail|message|msg|whatsapp|dm|page|form|site|website|call|script|notice|letter|correo|mensaje|courriel|nachricht)\b[^.\n]{{0,100}}?\b(?:ask\w*|request\w*|demand\w*|pid\w+|demand\w+|fragt|fragen|bhej\w*|share|enter|provide|send|reply\s+with)\b[^.\n]{{0,60}}?\b{_SECRET_NOUN}\b[^.\n]{{0,120}}?\b(?:account|block\w*|suspend\w*|lock\w*|expire\w*|urgent\w*|immediately|otherwise|or\s+(?:your|the)|warna|band|freeze|frozen)", needs_not_defensive=True),
    R("financial_fraud", "fake_message_plus_credentials", 90,
      r"(?:(?:correo|mensaje|sms|email|e-?mail|pagina|web|llamada|carta)\s+(?:falso|fraudulento|de\s+phishing)|(?:sms|e-?mail|mail|message|courriel|page)\s+(?:de\s+)?(?:phishing|hameconnage|frauduleux|faux)|"
      r"(?:betruegerische\w*|betrugerische\w*|gefalschte\w*|falsche[nr]?)\s+(?:e-?mail|nachricht|sms)|phishing[\s-]?(?:sms|email|mail|nachricht|page)|"
      r"(?:fake|jali|jaali)\s+(?:sms|message|email|msg|call|website|link))\b[^.\n]{0,160}?"
      r"(?:contrasena|clave|otp|codigo|pin|tarjeta|cvv|numero\s+de\s+tarjeta|seguridad|code|mot\s+de\s+passe|confirmation|identifiants|tan|passwort|kennwort|zugangsdaten|cnic|password|card|account)", needs_not_defensive=True),
    R("financial_fraud", "roman_urdu_secret_solicitation", 90,
      r"\b(?:otp|pin|cnic|password|cvv|card\s+number)\b[^.\n]{0,70}\b(?:bhej\w*|share\s+kar\w*|bata\w*|batao|de\s*(?:den|do|dein|dijiye)|dijiye|send\s+kar\w*)\b[^.\n]{0,100}\b(?:block|band|suspend|expire|warna|otherwise|account)|\b(?:account|card)\b[^.\n]{0,40}\b(?:block|band|suspend)\s+(?:ho|hojaye|ho\s+jaye\w*|ho\s+jayega)\b[^.\n]{0,80}\b(?:otp|pin|cnic|password|cvv)\b|\bsms\s+(?:banao|likho|likhein|likhiye|tayar)\b[^.\n]{0,80}\b(?:otp|pin|cnic|password)\b|\b(?:otp|pin|cnic)\b[^.\n]{0,80}\bsms\s+(?:banao|likho|likhein|likhiye|tayar)\b"),
    R("financial_fraud", "fake_document_for_deception", 90,
      rf"\b(?:fake|forged|fabricat\w+|counterfeit|doctored|falsif\w+|photoshop\w*|phony|bogus)\s+(?:\w+\s+){{0,2}}(?:bank\s+statements?|statements?|invoices?|pay\s*slips?|salary\s+slips?|employer\s+letter|id(?:entity)?\s+(?:cards?|documents?|papers?)|passports?|cheques?|checks?|tax\s+returns?|receipts?|documents?|ssns?|driver'?s?\s+licen[cs]es?|degrees?|certificates?|reviews?|testimonials?|prospectus|brochure|payslips?)\b[^.\n]{{0,160}}?{_STRONG_INTENT}|\b(?:generate|create|make|prepare|draft|produce)\b[^.\n]{{0,25}}\b(?:fake|forged|fabricated|counterfeit)\b[^.\n]{{0,60}}\b(?:identity\s+documents?|ids?|ssns?|passports?)\b[^.\n]{{0,80}}\b(?:open\s+(?:bank\s+)?accounts?|in\s+other\s+people'?s\s+names?|someone\s+else|loan|visa)", needs_not_defensive=True),
    R("financial_fraud", "fake_document_craft", 55,
      rf"{_CRAFT}\b[^.\n]{{0,30}}?\b(?:fake|forged|fabricat\w+|counterfeit|doctored|falsif\w+|phony|bogus)\s+(?:\w+\s+){{0,2}}(?:bank\s+statements?|invoices?|pay\s*slips?|payslips?|employer\s+letters?|id(?:entity)?\s+(?:cards?|documents?)|passports?|cheques?|tax\s+returns?|receipts?)", needs_not_defensive=True),
    R("financial_fraud", "guaranteed_returns_pitch", 85,
      rf"{_CRAFT}\b[^.\n]{{0,80}}?\b(?:guarantee[ds]?|guaranteeing|assured|risk[\s-]*free|zero[\s-]*risk|no[\s-]*risk|without\s+(?:any\s+)?risk|100\s?%\s+safe|sure[\s-]*shot|can'?t\s+lose)\b[^.\n]{{0,50}}?\b(?:returns?|profits?|income|roi|gains?|payouts?|yield)\b|"
      rf"{_CRAFT}\b[^.\n]{{0,100}}?\b\d{{1,3}}\s?%\s*(?:a|per|every|each|/)?\s*(?:day|daily|week|weekly|month|monthly)\b[^.\n]{{0,30}}\b(?:returns?|profit|roi|interest|gains?)\b[^.\n]{{0,80}}\b(?:investors?|pension|retire\w*|elderly|deposits?|pitch|scheme|promot\w+)|"
      rf"\b(?:pressure|convince|persuade|lure|recruit)\w*\s+(?:\w+\s+){{0,3}}(?:retirees|elderly|seniors|investors|people|victims|pensioners)\b[^.\n]{{0,80}}\b(?:pension|savings|money|funds|crypto|scheme)\b|"
      rf"\b(?:marketing\s+copy|pitch|brochure|advert\w*|post|ad)\b[^.\n]{{0,60}}\b(?:promis\w+|guarantee\w*)\b[^.\n]{{0,60}}\b\d{{1,3}}\s?%\s*(?:a|per|every|each|/)?\s*(?:day|daily|week|weekly|month|monthly)\b[^.\n]{{0,60}}\b(?:no\s+risk|risk[\s-]*free|guaranteed|collect\w*\s+(?:more\s+)?deposits)", needs_not_defensive=True),
    R("financial_fraud", "named_scheme_operational", 84,
      rf"{_CRAFT}\b[^.\n]{{0,70}}?\b(?:ponzi|pyramid\s+scheme|pump[\s-]*and[\s-]*dump|rug\s*pull|exit\s+scam|money\s+mule|advance[\s-]*fee\s+(?:fraud|scam)|romance\s+scam|pig[\s-]*butchering|carding|419\s+scam)\b|\b(?:pump[\s-]*and[\s-]*dump)\b[^.\n]{{0,80}}\b(?:message|telegram|post|hype|insiders?|penny\s+stock)\b|\bponzi\s+scheme\s+(?:we|i)\s+run\b|\b(?:lure|trick|recruit)\w*[^.\n]{{0,40}}\bponzi\b", needs_not_defensive=True),
    R("financial_fraud", "aml_structuring", 88,
      r"\b(?:structur(?:e|ing)|smurf(?:ing)?|split(?:ting)?|break(?:ing)?\s+(?:up|down)|divid(?:e|ing))\b[^.\n]{0,60}\b(?:cash|deposits?|transactions?|transfers?|sum|amount|payments?|money)\b[^.\n]{0,80}\b(?:under|below|beneath|less\s+than|avoid|without|so\s+(?:that\s+)?(?:the\s+)?(?:bank|compliance|they|it)|evade|dodge|(?:never|not|won'?t)\s+(?:notice|flag|report|detect))", needs_not_defensive=True),
    R("financial_fraud", "money_laundering_how_to", 88,
      r"\blaunder(?:ing)?\b[^.\n]{0,70}\b(?:money|cash|funds|proceeds|\$\s?\d|\d+\s?k\b)\b[^.\n]{0,100}\b(?:without|undetected|caught|through|using|via|best\s+way)\b|\b(?:best\s+way|how)\b[^.\n]{0,25}\blaunder\w*\b", needs_not_defensive=True),
    R("financial_fraud", "evade_kyc_aml", 82,
      r"\b(?:avoid|evade|bypass|get\s+around|dodge|circumvent|beat)\b[^.\n]{0,25}\b(?:aml|kyc|anti[\s-]*money|know\s+your\s+customer|reporting\s+requirements?|ctr\b|transaction\s+monitoring|sanctions\s+screening)", needs_not_defensive=True),
    R("financial_fraud", "stolen_card_data", 88,
      r"\b(?:stolen|hacked|leaked|dumped|carded|cloned|fullz)\b[^.\n]{0,25}\b(?:credit\s+cards?|debit\s+cards?|cards?|card\s+(?:numbers?|data|details)|cc\b|identities|identity|accounts?)\b[^.\n]{0,80}\b(?:cash\s*out|use|buy|sell|monetiz\w+|spend|withdraw|get\s+money|list|generate|give|find|where|without)\b|\b(?:list|generate|give\s+me|dump|share|provide|find)\b[^.\n]{0,30}\b(?:valid|working|live|real|active|fresh)\b[^.\n]{0,15}\b(?:credit\s+cards?|cc|cards?)\b[^.\n]{0,25}\b(?:numbers?|details|dumps?|data)\b|\bcash\s*out\b[^.\n]{0,40}\bstolen\b", needs_not_defensive=True),
    R("financial_fraud", "bec_executive_payment_secrecy", 90,
      r"(?:\b(?:this\s+is|i\s*(?:am|'m)|message\s+from|email\s+from|pos(?:e|ing)\s+as|pretend(?:ing)?\s+(?:to\s+be|i\s+am)|looks?\s+like\s+it'?s\s+from|looks?\s+like\s+it\s+is\s+from|from)\s+(?:the\s+|your\s+|our\s+)?(?:ceo|cfo|coo|cto|md|managing\s+director|chairman|president|director|boss|owner|head\s+of\s+finance|finance\s+director|manager|supervisor)\b)[^.\n]{0,160}?\b(?:wire|transfer|pay(?:ment)?|send|release|remit|disburse|purchase|buy|process|settle)\b[^.\n]{0,160}?\b(?:confidential(?:ly)?|secret(?:ly)?|(?:do\s*n'?o?t|don'?t|never|not)\s+(?:tell|inform|loop|involve|mention|call|contact|ask|verify|check|phone|notify)|keep\s+(?:this\s+|it\s+)?(?:quiet|private|between\s+us|confidential|secret)|reply\s+only\s+to\s+me|no\s+(?:need|time)\s+(?:to|for)\s+(?:verify|verification|approval|call|check)|without\s+(?:the\s+usual\s+|any\s+|further\s+)?(?:verification|approval|callback|confirmation|checking)|skip\s+(?:the\s+)?(?:usual\s+)?(?:verification|approval|callback|checks?|process)|bypass|not\s+to\s+loop|loop\s+in\s+anyone|call\s+back)", needs_not_defensive=True),
    R("financial_fraud", "bec_exec_secrecy_reverse", 88,
      r"\b(?:wire|transfer|pay|send|release|purchase|buy)\b[^.\n]{0,100}\b(?:confidential|secret(?:ly)?|(?:do\s*n'?o?t|don'?t|never)\s+(?:tell|inform|loop|involve|mention)\s+(?:anyone|anybody|finance|the\s+team|others?)|keep\s+(?:this\s+|it\s+)?(?:quiet|between\s+us|confidential|secret)|reply\s+only\s+to\s+me)\b[^.\n]{0,100}\b(?:ceo|cfo|director|boss|manager|owner|president)\b|\b(?:ceo|cfo|director|boss|manager|owner|president)\b[^.\n]{0,120}\b(?:wire|transfer|pay|send|release|purchase|buy)\b[^.\n]{0,100}\b(?:confidential|secret(?:ly)?|keep\s+(?:this\s+)?(?:quiet|between\s+us|confidential|secret)|don'?t\s+tell\s+anyone|do\s+not\s+tell\s+anyone)", needs_not_defensive=True),
    R("financial_fraud", "vendor_bank_change_no_verification", 86,
      r"(?:\b(?:vendor|supplier|payee|beneficiary|contractor|client|partner|company)'?s?\s+(?:new\s+)?(?:bank|account|payment|wire|banking)\s*(?:details|account|information|info|instructions|number)?\s*(?:has|have|had|were|was|are|is)?\s*(?:chang\w+|updat\w+|switch\w+|moved|different|new)|\b(?:new|updated|changed|different)\s+(?:bank|account|banking|wire|payment)\s+(?:details|account|information|instructions|number)\b)[^.\n]{0,160}?\b(?:(?:do\s*n'?o?t|don'?t|never|no\s+need\s+to|without|skip|not\s+to)\s+(?:\w+\s+){0,3}(?:phone|call|verify|verification|callback|call[\s-]?back|double[\s-]*check\w*|confirm\w*|check)|(?:pay|wire|transfer|send)\b[^.\n]{0,40}\b(?:right\s+now|immediately|today|asap|urgent\w*)\b[^.\n]{0,60}\b(?:do\s*n'?o?t|don'?t|without|skip|no)\b)", needs_not_defensive=True),
    R("financial_fraud", "verbal_approval_release_payments", 88,
      r"\b(?:signed\s+off|approved|authori[sz]ed|cleared|okayed)\b[^.\n]{0,25}\b(?:verbally|by\s+phone|over\s+the\s+phone|in\s+a\s+call|in\s+person)\b[^.\n]{0,100}\b(?:release|pay|transfer|wire|send|approve|process)\b[^.\n]{0,60}\b(?:all|every|pending|outstanding|queued|vendor|payments?|transfers?|funds)\b|\b(?:release|approve|pay|wire|transfer)\b[^.\n]{0,30}\b(?:all|every)\s+(?:pending|outstanding|queued|open)\s+(?:vendor\s+)?(?:payments?|invoices?|transfers?|transactions?|payouts?)\b[^.\n]{0,70}\b(?:without|skip|ignore|no\s+need)\b", needs_not_defensive=True),
    R("financial_fraud", "authorized_verbally_transfer", 86,
      r"\b(?:transfer|wire|send|pay|move)\b[^.\n]{0,40}\$?\s?\d[\d,]*[^.\n]{0,60}\b(?:ceo|cfo|director|boss|manager|owner|president)\s+(?:has\s+)?(?:already\s+)?(?:authori[sz]ed|approved|signed\s+off)\b[^.\n]{0,25}\b(?:verbally|by\s+phone)\b[^.\n]{0,60}\b(?:no\s+(?:need|further)|without|skip|bypass)\b", needs_not_defensive=True),
    R("financial_fraud", "social_engineer_victim_for_secret_or_money", 88,
      rf"\b(?:convince|trick|persuade|manipulate|coerce|talk|get|make|fool|deceive|pressure|scare|guilt)\w*\s+(?:the\s+|a\s+|my\s+|an?\s+)?(?:target|victim|user|customer|client|person|people|someone|somebody|them|him|her|elderly|old|senior|retiree|widow|stranger|mark|lonely|retirees)\b[^.\n]{{0,90}}?\b(?:read|share|give|send|tell|reveal|hand\s+over|disclose|provide|enter|say|forward|move|moving|transfer|invest|deposit|pay|wire|lend)\w*\b[^.\n]{{0,70}}?\b(?:{_SECRET_NOUN}|money|funds|cash|pension|savings|crypto|bitcoin|\$)", needs_not_defensive=True),
    R("financial_fraud", "romance_or_fake_story_for_money", 88,
      r"\b(?:lonely|widow|elderly|retiree|someone\s+i\s+(?:met|am\s+(?:dating|chatting))|person\s+i'?m\s+dating|girlfriend|boyfriend|dating\s+online|online\s+match)\b[^.\n]{0,120}\b(?:lend|send|wire|give|transfer|pay|loan)\b[^.\n]{0,40}\b(?:money|funds|cash|\$\s?\d|crypto|bitcoin|savings)\b[^.\n]{0,100}\b(?:made[\s-]*up|fake|fabricated|false|invented|fictional)\s+(?:\w+\s+)?(?:story|emergency|reason|excuse|illness|accident)|\b(?:made[\s-]*up|fake|fabricated|false|invented)\s+(?:medical\s+)?(?:emergency|story|illness|accident|hospital)\b[^.\n]{0,100}\b(?:send|wire|lend|transfer|money|\$\s?\d|funds)\b|\b(?:send|wire|lend|transfer|money|\$\s?\d)\b[^.\n]{0,100}\b(?:made[\s-]*up|fake|fabricated|false|invented)\s+(?:medical\s+)?(?:emergency|story|illness|accident|hospital)\b", needs_not_defensive=True),
    R("financial_fraud", "tech_support_scam", 86,
      rf"(?:{_CRAFT}|pos(?:e|ing)|pretend\w*|claim\w*|says?)\b[^.\n]{{0,80}}\b(?:virus|infected|hacked|malware|compromised|remote\s+access)\b[^.\n]{{0,100}}\b(?:call\s+(?:this|the|our)\s+number|pay|gift\s*cards?|\$\s?\d|payment)\b", needs_not_defensive=True),
    R("financial_fraud", "phishing_page_clone", 92,
      r"\b(?:mimics?|clone[sd]?|cop(?:y|ies)|replica|look[\s-]*alike|imitat\w+|fake|spoof\w*|phishing)\b[^.\n]{0,40}\b(?:login|sign[\s-]*in|bank(?:ing)?|payment|checkout|portal|webpage|web\s+page|website|page|screen|site)\b[^.\n]{0,100}\b(?:credentials?|passwords?|(?:user\s*name|login)\s+(?:and|&)\s+password|sends?\s+(?:the\s+)?(?:entered|typed|submitted)|captur\w+|harvest\w*|steal\w*|collect\w*|logs?\s+(?:the\s+)?(?:passwords?|credentials)|to\s+my\s+(?:server|email))", needs_not_defensive=True),
    R("financial_fraud", "advance_fee_scam", 86,
      r"\b(?:registration|processing|application|security|clearance|admin(?:istration)?|training|visa|insurance|verification|release|handling|advance)\s+fee\b[^.\n]{0,100}\b(?:job|loan|prize|lottery|inheritance|visa|grant|scholarship|approval|release|claim|winnings|parcel|customs)\b[^.\n]{0,120}\b(?:does\s+not\s+exist|doesn'?t\s+exist|fake|trick\w*|lure|victims?|pressure|scam|non-?existent)\b|\b(?:trick\w*|lure|fool|deceive)\b[^.\n]{0,50}\b(?:people|victims?|them|users?)\b[^.\n]{0,50}\b(?:advance|registration|processing|upfront)\s+fee\b|\b(?:guaranteed|instant|100\s?%)\s+(?:loan|credit|approval|grant|visa|job)\b[^.\n]{0,60}\b(?:fee|deposit|payment|upfront|advance)\b|\b(?:send|pay)\b[^.\n]{0,30}\$?\d+[^.\n]{0,25}\b(?:processing|registration|release|advance)\s+fee\b[^.\n]{0,25}\bfirst\b", needs_not_defensive=True),
    R("financial_fraud", "authority_impersonation_threat", 90,
      r"\b(?:pretend|pos(?:e|ing)|impersonat\w+|act(?:ing)?\s+as|claim(?:ing)?\s+to\s+be)\b[^.\n]{0,25}\b(?:irs|tax\s+(?:authority|department|office|collector)|fbr|hmrc|police|fbi|court|customs|government|law\s+enforcement|immigration|social\s+security|nadra|bisp|ehsaas|state\s+bank)\b[^.\n]{0,100}\b(?:arrest|jail|prison|fine|warrant|lawsuit|deport|pay|payment|gift\s*cards?|immediately|suspend|block|prize|won)", needs_not_defensive=True),
    R("financial_fraud", "gift_card_code_scam", 84,
      r"\b(?:gift\s*cards?|itunes|google\s+play\s+card|steam\s+card|vanilla\s+card)\b[^.\n]{0,60}\b(?:codes?|numbers?|pins?|scratch|serial|photos?\s+of\s+the\s+back|send\s+(?:me|us|them))\b|\b(?:buy|purchase)\b[^.\n]{0,30}\b(?:gift\s*cards?)\b[^.\n]{0,60}\b(?:send|read|share|give|provide)\b", needs_not_defensive=True),
    R("financial_fraud", "urgent_gift_card_request_secrecy", 88,
      r"\b(?:pos(?:e|ing)|pretend(?:ing)?|as)\b[^.\n]{0,30}\b(?:manager|boss|ceo|cfo|director|supervisor)\b[^.\n]{0,80}\bgift\s*cards?\b[^.\n]{0,80}\b(?:reply\s+only\s+to\s+me|don'?t\s+call|do\s+not\s+call|secret|confidential|don'?t\s+tell)", needs_not_defensive=True),
    R("financial_fraud", "fake_account_verify_link", 85,
      rf"{_IMPERSON}[^.\n]{{0,60}}?\b(?:paypal|bank|amazon|apple|microsoft|netflix|support|account)\b[^.\n]{{0,120}}?\b(?:verify|confirm|update|validate|unlock|restore|reactivate|log\s*in|sign\s*in)\b[^.\n]{{0,40}}\b(?:their|your|the\s+user'?s|users'?|customers'?|account|card|identity)\b[^.\n]{{0,80}}\b(?:link|url|page|site|website|click|portal|card\s+details|details)", needs_not_defensive=True),

    R("financial_fraud", "fake_page_collects_secrets", 90,
      rf"\b(?:fake|phishing|spoof\w*|fraudulent|clone[sd]?)\s+(?:\w+\s+){{0,3}}(?:page|site|website|app|form|portal|airdrop)\b[^.\n]{{0,60}}\b(?:asks?|prompts?|requests?|requires?|collects?|captures?|harvests?)\b[^.\n]{{0,40}}\b{_SECRET_NOUN}", needs_not_defensive=True),
    R("financial_fraud", "overpayment_check_scam", 88,
      r"\boverpayment\s+(?:check|cheque)\b[^.\n]{0,120}\b(?:deposit|refund|wire\s+(?:me\s+)?back|send\s+(?:me\s+)?back|difference)\b|\b(?:deposit|cash)\b[^.\n]{0,30}\b(?:overpayment|overpaid)\b[^.\n]{0,60}\b(?:wire|send|refund|return)\b", needs_not_defensive=True),
    R("financial_fraud", "caller_claims_institution_requests_secret", 88,
      rf"\b(?:i\s*(?:am|'m)|this\s+is|we\s+are|calling)\s+(?:from|with|at)\s+(?:the\s+|your\s+)?(?:\w+'?s?\s+){{0,2}}(?:bank|security|fraud|it|support|tax|police|microsoft|apple|amazon|paypal)\b[^.\n]{{0,80}}\b(?:read|give|tell|send|share|provide|confirm)\s+(?:me|us|back)\s+(?:the\s+|your\s+)?(?:customer'?s?\s+)?(?:full\s+)?(?:\w+\s+)?{_SECRET_NOUN}", needs_not_defensive=True),
    R("financial_fraud", "exfiltrate_via_fake_support", 88,
      rf"{_IMPERSON}[^.\n]{{0,120}}\b(?:get|make|have)\s+(?:them|him|her|the\s+(?:victim|customer|user|person))\s+(?:to\s+)?(?:tell|read|share|give|send|say)\b[^.\n]{{0,60}}\b{_SECRET_NOUN}", needs_not_defensive=True),
]

ALL_RULES: list[Rule] = INJECTION_RULES + FRAUD_RULES

# Compile multilingual override and extraction rules (generated).
for _lang, _verb, _noun in _LANG_OVERRIDES:
    _gap = r".{0,14}" if _lang in {"zh", "ja", "ko"} else r"(?:\s+\S+){0,6}?\s+"
    _pat = rf"{_verb}{_gap if _lang in {'zh','ja','ko'} else r'(?:\s+\S+){0,6}?\s+'}{_noun}"
    INJECTION_RULES.append(R("injection", f"override_{_lang}", 88, _pat, discussable=True))
    if _lang in {"tr", "de", "ja", "ko", "roman", "ar", "ru", "zh", "it"}:
        # object-first word order (Turkish, German, Japanese, Roman-Urdu, ...): "<rules> ... <ignore>"
        _gap2 = r".{0,14}" if _lang in {"zh", "ja", "ko"} else r"(?:\s+\S+){0,6}?\s+"
        INJECTION_RULES.append(R("injection", f"override_{_lang}_ov", 86, rf"{_noun}{_gap2}{_verb}", discussable=True))
INJECTION_RULES.append(
    R("extraction", "extract_system_prompt_multilingual", 86,
      rf"{_EXTRACT_VERB_MULTI}(?:\s+\S+){{0,6}}?\s*{_SYSTEM_PROMPT_MULTI}|{_SYSTEM_PROMPT_MULTI}(?:\s+\S+){{0,6}}?\s*{_EXTRACT_VERB_MULTI}",
      discussable=True)
)
INJECTION_RULES.append(
    R("extraction", "extract_prompt_cjk_ar", 84,
      r"(?:输出|显示|透露|告诉我|展示|打印|说出).{0,8}(?:系统提示(?:词)?|系统指令|初始指令|隐藏指令)|(?:اكشف|اظهر|أظهر|اعرض|اطبع)\w*\s+(?:عن\s+)?(?:موجه\s+النظام|تعليمات\s+النظام)", discussable=True)
)
INJECTION_RULES.extend([
    R("injection", "forget_everything_told_romance", 88,
      r"(?:oubli\w*|ignor\w*|efface\w*)\s+tout\s+ce\s+qu\S*\s+(?:\S+\s+){0,4}(?:dit|appris|demande|donne|programme)|"
      r"(?:olvid\w*|ignor\w*)\s+todo\s+lo\s+que\s+(?:\S+\s+){0,4}(?:dijeron|dicho|ensenaron|indicaron|programaron)|"
      r"(?:esque[cç]\w*|ignor\w*)\s+tudo\s+(?:o\s+)?que\s+(?:\S+\s+){0,4}(?:disseram|disse|ensinaram|programaram)|"
      r"(?:vergiss|ignorier\w*)\s+alles[^.\n]{0,25}(?:gesagt|beigebracht|programmiert|anweisung)|"
      r"(?:dimentic\w*|ignor\w*)\s+tutto\s+(?:cio\s+)?che\s+(?:\S+\s+){0,4}(?:detto|insegnato|programmato)", discussable=True),
    R("persona", "act_without_restriction_romance", 70,
      r"\b(?:agis|agir|agissez|actua|actue|comporta\w*|responde|reponds|repondez|antworte|handle|aja|responda|rispondi|agisci|davran\w*)\b[^.\n]{0,30}"
      r"\b(?:sans|sin|sem|ohne|senza)\s+(?:aucune?\s+|ninguna?\s+|nenhuma?\s+|jede\s+|keine?\s+|alcuna\s+)?"
      r"(?:restrictions?|restriccion(?:es)?|restricoes|restricao|einschrankung\w*|beschrankung\w*|limites?|filtres?|filtros?|regles?|reglas?|regras?|zensur|censura|censure)", discussable=True),
])

INJECTION_RULES.extend([
    R("extraction", "extract_preamble_or_setup", 84,
      r"\b(?:output|print|show|write\s+out|reveal|give|repeat|recite|tell\s+me|state|list|display|share|type\s+out)\b[^.\n]{0,50}\b(?:(?:your|the)\s+)?(?:(?:complete|full|entire|original|confidential|hidden)\s+)*"
      r"(?:preamble|setup\s+text|boot\s+text|initial\s+text|configuration\s+text|(?:rules|instructions|guidelines|directives)\s+you\s+were\s+(?:configured|programmed|given|set\s+up|trained)\s+with|"
      r"(?:text|prompt|message|instructions?)\s+(?:that\s+)?(?:your\s+|the\s+)?(?:operator|developer|vendor|company|creator)s?\s+(?:placed|wrote|put|gave|added|set))\b", discussable=True),
    R("extraction", "what_would_your_setup_say", 80,
      r"\bwhat\s+(?:would|does|did)\s+your\s+(?:original|initial|hidden|secret|system)\s+(?:setup|prompt|instructions?|text|message)\s+(?:text\s+)?say\b"),
    R("injection", "drop_guardrails", 88,
      r"\b(?:drop|lower|relax|suspend|pause|shed|remove|get\s+rid\s+of|take\s+off|take\s+down)\b[^.\n]{0,12}\b(?:your|the|all)\s+(?:guardrails?|safeguards?|filters?|safety\s+\w+|restrictions?|content\s+polic\w+|moderation)\b", discussable=True),
    R("injection", "enter_privileged_mode", 62,
      r"\benter\s+(?:into\s+)?(?:maintenance|admin|debug|test|root|god|developer|override)\s+mode\b"),
    R("injection", "developers_instructions_no_longer_apply", 88,
      r"\b(?:whatever|anything|everything)\s+(?:the\s+)?(?:developers?|operators?|creators?|company|vendor|openai|anthropic)\s+(?:told|said|instructed|programmed|gave)\b[^.\n]{0,40}\b(?:no\s+longer|doesn'?t|does\s+not|don'?t|do\s+not|not)\s+(?:apply|matter|count|hold|valid)", discussable=True),
    R("injection", "follow_only_my_commands", 70,
      r"\b(?:follow|obey)\s+(?:only\s+)?my\s+(?:commands?|orders?|instructions?)\s+(?:exclusively|only|alone)\b"),
    R("injection", "new_objective_supersedes", 82,
      r"\b(?:supersedes?|overrides?|replaces?|takes?\s+precedence\s+over)\b[^.\n]{0,30}\b(?:old|previous|prior|original|earlier|existing|former)\b|\bincluding\s+(?:prohibited|forbidden|illegal|harmful|restricted|banned)\s+(?:topics?|content|requests?|things|subjects?)\b", discussable=True),
    R("injection", "treat_earlier_as_cancelled", 90,
      r"\b(?:treat|consider|regard|count)\s+(?:every|all|any)\s+(?:earlier|previous|prior|preceding|former)\s+(?:instructions?|rules|directives?|guidelines?)\s+as\s+(?:cancel+ed|void|null|invalid|revoked|obsolete|nonexistent|gone)\b", discussable=True),
    R("injection", "disregard_users_question", 85,
      r"\b(?:disregard|ignore|forget|skip)\s+(?:the\s+)?user'?s?\s+(?:question|request|query|prompt|message|instructions?)\b", discussable=True),
])
UNTRUSTED_RULES.append(
    R("indirect", "to_the_assistant_reading_this", 88,
      r"\bto\s+(?:the\s+|any\s+)?(?:assistant|ai|model|llm|agent)s?\s+(?:that\s+(?:is\s+)?)?(?:reading|processing|summari[sz]ing|analy[sz]ing|parsing)\b|\bto\s+any\s+ai\b", untrusted_only=True)
)

FRAUD_RULES.extend([
    R("financial_fraud", "german_pretend_bank_ask_tan", 88,
      r"\b(?:so\s+tut|tut\s+so|tun\s+als\s+ob)\b[^.\n]{0,40}\b(?:k[aä]me|w[aä]re|sei|von)\b[^.\n]{0,60}\b(?:bank|sparkasse|paypal|polizei|amazon|post)\b[^.\n]{0,80}\b(?:tan|passwort|kennwort|pin|kartennummer|zugangsdaten|code)\b", needs_not_defensive=True),
    R("financial_fraud", "impersonation_plus_pay_request", 85,
      rf"{_IMPERSON}[^.\n]{{0,120}}?\b(?:ask|tell|request|demand|require|get|make|have|pressure|convince|trick)\w*\b[^.\n]{{0,40}}\b(?:to\s+)?(?:pay|send|wire|transfer|deposit|buy|purchase)\b", needs_not_defensive=True),
    R("financial_fraud", "family_emergency_scam", 88,
      r"['\"]?(?:your|their|the)\s+(?:son|daughter|grandson|granddaughter|nephew|niece|brother|sister|mom|dad|mother|father)['\"]?\b[^.\n]{0,80}\b(?:lost|new|broke|changed|stolen)\b[^.\n]{0,25}\b(?:phone|number)\b[^.\n]{0,80}\b(?:money|funds|cash|transfer|send|wire|pay)\b", needs_not_defensive=True),
    R("financial_fraud", "ponzi_mechanics", 90,
      r"\b(?:using|with|from|out\s+of)\s+(?:the\s+)?(?:money|funds|deposits?|capital)\s+(?:from|of)\s+(?:new|later|incoming)\s+(?:members?|investors?|users?|depositors?|participants?)\b|\bpay(?:s|ing)?\s+(?:out\s+)?(?:earlier|existing|old|current)\s+(?:members?|investors?|users?)\b[^.\n]{0,40}\b(?:with|from|using)\b[^.\n]{0,25}\bnew\b", needs_not_defensive=True),
    R("financial_fraud", "stolen_identity_use", 88,
      r"\bstolen\s+(?:identit\w+|ids?|ssns?|personal\s+(?:data|information))\b[^.\n]{0,80}\b(?:open|create|use|accounts?|loans?|credit|move|launder)\b|\b(?:open|create)\b[^.\n]{0,25}\baccounts?\b[^.\n]{0,25}\b(?:with|using|in)\s+(?:stolen|fake|someone\s+else'?s|other\s+people'?s)\s+(?:identit\w+|names?|ids?|documents?)\b", needs_not_defensive=True),
    R("financial_fraud", "evade_detection_moving_money", 82,
      r"\b(?:move|transfer|withdraw|cash\s*out|send)\b[^.\n]{0,60}\b(?:before|so\s+that|so)\s+(?:the\s+)?(?:banks?|police|authorities|compliance|fraud\s+team|they)\s+(?:\w+\s+)?(?:catch|notice|find\s+out|detect|flag|freeze|trace)\w*|\bwithout\s+(?:triggering|tripping|raising|setting\s+off)\s+(?:any\s+)?(?:alerts?|alarms?|flags?|fraud\s+(?:checks?|detection))\b", needs_not_defensive=True),
    R("financial_fraud", "card_cloning_skimming", 86,
      r"\b(?:clon\w+|skimm\w+|duplicat\w+)\b[^.\n]{0,30}\b(?:debit|credit|atm|bank)\s+cards?\b", needs_not_defensive=True),
    R("financial_fraud", "fake_charity", 86,
      r"\b(?:fake|fraudulent|bogus|phony|sham)\s+(?:charity|fundraiser|donation|gofundme|crowdfund\w*|appeal)\b|\b(?:donations?|money|funds|contributions?)\b[^.\n]{0,40}\b(?:go|goes|going|sent|will\s+go)\s+(?:directly\s+)?to\s+my\s+(?:personal|own|private)\s+(?:account|wallet)\b", needs_not_defensive=True),
    R("financial_fraud", "recovery_fee_scam", 88,
      r"\b(?:recover|retrieve|release|claim|unlock)\w*\b[^.\n]{0,60}\b(?:investments?|funds|money|inheritance|savings|winnings)\b[^.\n]{0,70}\b(?:upfront|up-front|advance|processing|release|retainer)\s+fee\b", needs_not_defensive=True),
    R("financial_fraud", "lookalike_invoice_own_account", 88,
      r"\b(?:invoice|payment\s+request|bill)\b[^.\n]{0,40}\b(?:looks?|appears?)\s+like\b[^.\n]{0,60}\b(?:supplier|vendor|usual|real|legit\w*|genuine)\b[^.\n]{0,70}\b(?:my|our\s+own|a\s+different|another)\s+(?:own\s+)?(?:bank\s+)?account\b|\b(?:replace|swap|substitute)\b[^.\n]{0,25}\b(?:bank\s+(?:details|account)|iban)\b[^.\n]{0,40}\bwith\s+(?:mine|my)\b", needs_not_defensive=True),
])
ALL_RULES = INJECTION_RULES + FRAUD_RULES

# Short high-value English signatures for the squashed (letters-only) variant.
_SQUASHED_SIGNATURES = (
    "ignorepreviousinstructions", "ignoreallpreviousinstructions", "ignoreallpriorinstructions", "ignoreallpriorrules",
    "disregardpreviousinstructions", "disregardallpriorrules", "disregardallpreviousinstructions", "forgetpreviousinstructions",
    "forgetallpreviousinstructions", "forgetyourinstructions", "revealthesystemprompt", "revealyoursystemprompt",
    "printyoursystemprompt", "showmethesystemprompt", "showyoursystemprompt", "ignoreyourprogramming", "ignoreallsafetyrules",
    "bypassyoursafety", "youarenowunrestricted", "developermodeenabled", "overrideyoursafety",
)

_EDU_OPENER = re.compile(
    fold(r"^\s*(?:can\s+you\s+)?(?:please\s+)?(?:explain|define|describe|what\s+(?:is|are|does|do)|what'?s|how\s+(?:do|does|can|should|to)\s+(?:\w+\s+){0,4}(?:prevent|detect|defend|mitigate|stop|block|protect|test|work)|why\s+(?:do|does|is|are)|translate\s+the\s+(?:phrase|sentence|following)|give\s+me\s+(?:a|the)\s+definition|for\s+my\s+(?:course|class|paper|thesis))\b"),
    re.I,
)
_QUOTE_CHARS = "\"'“”‘’`«»"
_NEGATOR_BEFORE = re.compile(fold(r"(?:\bnot|\bnever|n'?t|\bcannot|\bwon'?t|\bwithout|\brefuse\s+to|\bunable\s+to|\bnor)\s*(?:\w+\s+)?$"), re.I)


def _sentence_bounds(text: str, pos: int) -> tuple[int, int]:
    start = max(text.rfind(".", 0, pos), text.rfind("\n", 0, pos), text.rfind("?", 0, pos), text.rfind("!", 0, pos))
    ends = [e for e in (text.find(".", pos), text.find("\n", pos), text.find("?", pos), text.find("!", pos)) if e != -1]
    return start + 1, (min(ends) if ends else len(text))


def _inside_quotes(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 3):start]
    after = text[end:end + 3]
    return any(c in before for c in _QUOTE_CHARS) and any(c in after for c in _QUOTE_CHARS)


def _is_discussion(text: str, match: re.Match[str]) -> bool:
    s, e = _sentence_bounds(text, match.start())
    sentence = text[s:e]
    if _EDU_OPENER.search(sentence):
        return True
    if _inside_quotes(text, match.start(), match.end()):
        window = text[max(0, s - 160):e]
        if re.search(fold(r"\b(?:translate|meaning|means?|example|phrase|sentence|slide|quote[sd]?|called|known\s+as|what\s+does|attack|technique|string)\b"), window, re.I):
            return True
    return False


def _negated(text: str, start: int) -> bool:
    return bool(_NEGATOR_BEFORE.search(text[max(0, start - 22):start]))


def _evidence(text: str, m: re.Match[str]) -> str:
    return text[max(0, m.start()):min(len(text), m.end())][:140]


def _aggregate(signals: list[IntentSignal]) -> int:
    if not signals:
        return 0
    by_name: dict[str, int] = {}
    for s in signals:
        by_name[s.name] = max(by_name.get(s.name, 0), s.weight)
    weights = sorted(by_name.values(), reverse=True)
    score = weights[0] + 0.30 * sum(weights[1:])
    return int(min(100, round(score)))


_NAMED_PERSONA = re.compile(
    r"(?:\b(?:you\s+are|you'?re|act\s+as|pretend\s+to\s+be|become|as|called|named|meet|introducing)\s+(?:now\s+)?(?:an?\s+)?(?:AI\s+)?(?:called\s+|named\s+)?"
    r"(?:DAN|STAN|DUDE|AntiGPT|EvilBot|BetterDAN|Mongo\s+Tom)\b|\b(?:DAN|STAN|DUDE|AntiGPT|BetterDAN)\s+(?:mode|jailbreak|prompt)\b|"
    r"\b(?:DAN|STAN|DUDE)\b[^.\n]{0,40}\b(?:who|that)\s+(?:has\s+no|never|can\s+do|strives)\b)"
)


def analyze_intent_text(text: str, *, untrusted: bool = False) -> IntentVerdict:
    """Analyse one text blob.  ``untrusted`` enables retrieved-content rules and a stricter bar."""
    verdict = IntentVerdict()
    if not text or not text.strip():
        return verdict
    variants = build_variants(text)
    original = next((v for v in variants if v.source == "original"), variants[0])

    defensive = bool(re.search(_DEFENSIVE_RX, original.text)) and not re.search(_rx(_STRONG_INTENT), original.text)
    pure_defensive_q = bool(_PURE_DEFENSIVE_START.search(original.text))
    verdict.defensive_context = defensive

    found: dict[tuple[str, str], IntentSignal] = {}
    rules = ALL_RULES + (UNTRUSTED_RULES if untrusted else [])
    for variant in variants:
        for rule in rules:
            m = rule.pattern.search(variant.text)
            if not m:
                continue
            weight = rule.weight
            if _negated(variant.text, m.start()) and rule.category in {"injection", "persona", "extraction"}:
                continue
            if rule.discussable and _is_discussion(variant.text, m):
                weight = max(0, weight - 55)
            if rule.needs_not_defensive:
                if _NEGATED_SOLICIT.search(variant.text[max(0, m.start() - 40):m.end() + 5]) and rule.name in {
                    "craft_message_soliciting_secrets", "impersonation_plus_credential_request"}:
                    continue
                if defensive or (pure_defensive_q and not re.search(_rx(_STRONG_INTENT), original.text)):
                    weight = max(0, weight - 60)
            if weight <= 0:
                continue
            key = (rule.category, rule.name)
            sig = IntentSignal(rule.category, rule.name, weight, _evidence(variant.text, m), variant.source)
            # keep the strongest / most original observation
            prev = found.get(key)
            if prev is None or sig.weight > prev.weight or (sig.weight == prev.weight and variant.source == "original"):
                found[key] = sig

    # Squashed variant signature check (catches letter-by-letter spacing with single spaces).
    squashed = re.sub(r"[^a-z0-9]", "", fold(_defuse_homoglyphs(text[:MAX_SCAN_CHARS])))
    if not any(s.category in {"injection", "extraction"} and s.weight >= BLOCK_THRESHOLD for s in found.values()):
        for sig_text in _SQUASHED_SIGNATURES:
            if sig_text in squashed and sig_text not in re.sub(r"[^a-z0-9]", "", original.text.replace(" ", "")) :
                found[("injection", "squashed_signature")] = IntentSignal(
                    "injection", "squashed_signature", 86, sig_text, "squashed")
                break
            if sig_text in squashed and not _normal_spacing_contains(original.text, sig_text):
                found[("injection", "squashed_signature")] = IntentSignal(
                    "injection", "squashed_signature", 86, sig_text, "squashed")
                break

    m_persona = _NAMED_PERSONA.search(text[:MAX_SCAN_CHARS])  # case-sensitive on purpose: "Dan" is a name
    if m_persona:
        found[("persona", "named_jailbreak_persona")] = IntentSignal(
            "persona", "named_jailbreak_persona", 80, m_persona.group(0)[:100], "original")

    signals = sorted(found.values(), key=lambda s: -s.weight)

    # Evasion bonus: the attack only becomes visible after de-obfuscation.
    obfuscated = False
    if signals:
        original_hit = any(s.variant == "original" and s.weight >= 50 for s in signals)
        strong_other = any(s.variant != "original" and s.weight >= 60 for s in signals)
        if strong_other and not original_hit:
            obfuscated = True
            signals.append(IntentSignal("obfuscation", "obfuscated_payload", 80, "attack visible only after normalisation", "multi"))

    # Untrusted content: any injection-category hit is more serious (instruction inside data).
    if untrusted:
        signals = [
            IntentSignal(s.category, s.name, min(100, s.weight + 10), s.evidence, s.variant)
            if s.category in {"injection", "persona", "extraction", "tool_abuse", "exfiltration"} else s
            for s in signals
        ]

    verdict.signals = signals
    verdict.obfuscated = obfuscated
    verdict.score = _aggregate(signals)
    # a lone weak signal (e.g. claimed_approval=45, system_prefix_line=40) must not block on its own
    verdict.verdict = "block" if verdict.score >= BLOCK_THRESHOLD else "allow"
    if verdict.blocked:
        cats: list[str] = []
        for s in signals:
            if s.weight >= 40 and s.category not in cats:
                cats.append(s.category)
        verdict.categories = cats
    return verdict


_DEFENSIVE_RX = _rx(_DEFENSIVE)


def _normal_spacing_contains(original_text: str, signature: str) -> bool:
    """True if the signature appears in the original with ordinary (single/no) spacing."""
    return signature in re.sub(r"[^a-z0-9]", "", original_text) and len(re.findall(r"\b\w\b", original_text)) < 4