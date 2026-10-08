"""The shapes of secrets: one list, for the commit-time scanner and for everything Sletchy prints.

`scripts/secret_scan.py` stops a key reaching a commit. Anything Sletchy shows a
person - a ledger body (`sletchy ledger show --payload`, #86), and later the SOC's view
of a command line (ADR-0011) - masks the same shapes before printing. Two copies of
this list would drift, so there is one (LAW 6).

**Standard library only, and it imports nothing from Sletchy.** CI runs the scanner with
a bare Python and no installed package, so the scanner loads this file by its path.

Shape matching is a backstop, not a guarantee: a secret in a shape this list does not
know is printed as it is (#86's stated gap, in `tests/adversarial/COVERAGE.md`).
"""

from __future__ import annotations

import re

#: (name, pattern). Lengths are a little short of the real thing, so a truncated or
#: wrapped key still matches. Anthropic comes before OpenAI: an Anthropic key also has
#: the OpenAI shape, and masking takes the first name that matches.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Groq", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    ("Anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("HuggingFace", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("Google", re.compile(r"AIza[A-Za-z0-9_-]{30,}")),
    ("GitHub", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("Slack", re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}")),
    ("AWS access key", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)

#: The pattern that leaked a key into eight files: a real secret as the *fallback
#: default* of an environment lookup, which works silently when the variable is missing.
FALLBACK_DEFAULT = re.compile(
    r"""(?:os\.environ\.get|os\.getenv)\s*\(\s*["'][A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*["']\s*,\s*["'][^"']{8,}["']""",
    re.IGNORECASE,
)


def mask(value: str) -> str:
    """Enough to find the key in a provider's console, not enough to use it."""
    return f"{value[:10]}...[{len(value)} chars]" if len(value) > 14 else "[redacted]"


#: A whole private key, header to footer. The scanner needs only the header to flag a
#: file; a display must hide the key itself, which is every line after it. With no
#: footer, everything after the header is hidden.
_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    r".*?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|\Z)",
    re.DOTALL,
)


def masked(text: str) -> tuple[str, tuple[str, ...]]:
    """`text` with every known secret replaced by `[secret: <shape>]`, and the shapes found.

    Nothing of the secret survives the replacement, not even the prefix `mask` keeps:
    this is for showing a body to a person, where the prefix serves no one.
    """
    found: list[str] = []
    text, blocks = _KEY_BLOCK.subn("[secret: Private key block]", text)
    if blocks:
        found.append("Private key block")
    for name, pattern in PATTERNS:
        text, count = pattern.subn(f"[secret: {name}]", text)
        if count:
            found.append(name)
    return text, tuple(found)
