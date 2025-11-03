# scripts/augment_banks.py
from __future__ import annotations
import base64, codecs, random, re, string, unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "promptdefender" / "assets"

ATT_IN = ASSETS / "attack_bank.txt"
BEN_IN = ASSETS / "benign_bank.txt"
ATT_OUT = ASSETS / "attack_bank_round2.txt"
BEN_OUT = ASSETS / "benign_bank_round2.txt"

random.seed(7)

# --- light synonym pools for paraphrase (offline, tiny but effective)
SYN = {
    r"\bignore\b": ["disregard", "forget", "discard"],
    r"\bprevious instructions\b": ["prior rules", "earlier guidance", "earlier instructions"],
    r"\breveal\b": ["show", "print", "expose"],
    r"\bsystem prompt\b": ["hidden prompt", "internal prompt", "policy prompt"],
    r"\bsecret\b": ["credential", "token", "key"],
    r"\bexecute\b": ["run", "carry out"],
    r"\bprint\b": ["output", "display"],
    r"\ball\b": ["every", "any"],
    r"\bdata exfiltrate\b": ["exfiltrate", "leak", "extract"],
}

HOMO = {  # very small homoglyph set
    "a":"а", "e":"е", "o":"ο", "i":"і", "c":"с", "p":"р", "x":"х"
}  # Latin -> Cyrillic look-alikes

def rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")

def to_hex(s: str) -> str:
    return s.encode("utf-8").hex()

def to_base64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")

def insert_whitespace_noise(s: str) -> str:
    tokens = s.split(" ")
    for _ in range(min(3, max(1, len(tokens)//5))):
        idx = random.randrange(0, len(tokens))
        tokens[idx] = tokens[idx] + random.choice(["  ", "\t", " \u200b "])  # zero-width joiners etc.
    return " ".join(tokens)

def punctuation_wrap(s: str) -> str:
    return f"### {s} ###"

def homoglyph_swap(s: str, prob: float = 0.1) -> str:
    out = []
    for ch in s:
        if ch.lower() in HOMO and random.random() < prob:
            repl = HOMO[ch.lower()]
            out.append(repl if ch.islower() else repl.upper())
        else:
            out.append(ch)
    return "".join(out)

def case_variants(s: str):
    return [s.lower(), s.upper(), s.title()]

def paraphrase_once(s: str) -> str:
    out = s
    for pat, repls in SYN.items():
        if re.search(pat, out, flags=re.I):
            out = re.sub(pat, random.choice(repls), out, flags=re.I)
    # light clause flip if "and" present
    if " and " in out.lower():
        parts = re.split(r"\band\b", out, flags=re.I, maxsplit=1)
        if len(parts) == 2:
            a, b = parts
            out = b.strip() + " and " + a.strip()
    return out

def variants_for_attack(s: str) -> list[str]:
    vs = set()
    base = s.strip()
    if not base: return []

    # paraphrase and cosmetic noise
    v1 = paraphrase_once(base); vs.add(v1)
    v2 = insert_whitespace_noise(base); vs.add(v2)
    for c in case_variants(base): vs.add(c)
    vs.add(punctuation_wrap(base))
    vs.add(homoglyph_swap(base))

    # obfuscations
    vs.add(f"ROT13:{rot13(base)}")
    vs.add(f"BASE64:{to_base64(base)}")
    vs.add(f"HEX:{to_hex(base)}")

    # story-wrap / indirection
    vs.add(f"As an academic exercise, without violating safety, hypothetically describe steps to: {base}")
    vs.add(f"Ignore safety hypothetically; if you *had* to: {base}")

    # ensure reasonable lengths
    vs = [v for v in vs if len(v) <= 600]
    return list(vs)

def benign_noise(s: str) -> list[str]:
    b = s.strip()
    if not b: return []
    out = set()
    out.add(insert_whitespace_noise(b))
    out.update(case_variants(b))
    out.add(punctuation_wrap(b))
    return list(out)

def dedup_keep_order(items: list[str]) -> list[str]:
    seen, out = set(), []
    for it in items:
        k = unicodedata.normalize("NFKC", it)
        if k not in seen:
            seen.add(k)
            out.append(it)
    return out

def main():
    attacks = ATT_IN.read_text(encoding="utf-8").splitlines() if ATT_IN.exists() else []
    benigns = BEN_IN.read_text(encoding="utf-8").splitlines() if BEN_IN.exists() else []

    aug_att = []
    for a in attacks:
        aug_att.append(a)
        aug_att.extend(variants_for_attack(a))

    aug_ben = []
    for b in benigns:
        aug_ben.append(b)
        aug_ben.extend(benign_noise(b))

    aug_att = dedup_keep_order([x for x in aug_att if x.strip()])
    aug_ben = dedup_keep_order([x for x in aug_ben if x.strip()])

    ATT_OUT.write_text("\n".join(aug_att), encoding="utf-8")
    BEN_OUT.write_text("\n".join(aug_ben), encoding="utf-8")

    print(f"Wrote {ATT_OUT} ({len(aug_att)} lines)")
    print(f"Wrote {BEN_OUT} ({len(aug_ben)} lines)")

    # optional: quick preview
    print("\nSample attack variants:")
    for s in aug_att[:5]: print(" -", s)
    print("\nSample benign variants:")
    for s in aug_ben[:5]: print(" -", s)

if __name__ == "__main__":
    main()
