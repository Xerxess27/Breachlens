#!/usr/bin/env python3
"""BreachLens: check whether your email and passwords have leaked in data breaches.

It tells you which breaches exposed your email, what kind of data leaked
(passwords, phone, address...), how bad it is, and exactly what to do about it.
It can also check whether a specific password has been exposed — WITHOUT ever
sending the password anywhere (it uses k-anonymity: only the first 5 characters
of the password's hash leave your computer).

Data sources:
  * XposedOrNot  — free, no API key needed (the default email source)
  * Have I Been Pwned — optional, more authoritative (set a HIBP API key)
  * Pwned Passwords — free, no key, privacy-preserving password checks

What it does NOT do: it never downloads stolen password dumps or reveals other
people's plaintext passwords. It reports breach exposure and remediation only.

Only look up email addresses and passwords that are yours or that you have
permission to check.

Quick start:
    python3 breachlens.py demo                     # see a sample report, no network
    python3 breachlens.py check you@example.com    # check an email
    python3 breachlens.py password                 # check a password (hidden input)
    python3 breachlens.py serve                    # web UI at http://127.0.0.1:8088
    python3 breachlens.py report you@example.com -o report.html
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import html
import json
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
USER_AGENT = f"BreachLens/{VERSION} (personal breach self-check)"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HIBP_KEY_RE = re.compile(r"^[a-f0-9]{32}$", re.I)

# --------------------------------------------------------------------------- terminal

class Color:
    on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if Color.on else str(s)


def red(s): return _c("1;31", s)
def green(s): return _c("32", s)
def yellow(s): return _c("33", s)
def cyan(s): return _c("36", s)
def bold(s): return _c("1", s)
def dim(s): return _c("2", s)


def die(msg, code=1):
    print(red("error: ") + msg, file=sys.stderr)
    sys.exit(code)


def esc(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


# --------------------------------------------------------------------------- data model

# Each kind of leaked data, mapped to a severity. Order matters for "worst first".
SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

DATA_SEVERITY = [
    # (severity, keywords found in a data-class name)
    ("critical", ("password", "credit card", "bank", "cvv", "card number", "social security",
                  "ssn", "security question", "security answer", "pin", "crypto", "credentials")),
    ("high", ("phone", "physical address", "home address", "mailing address", "date of birth",
              "dob", "government", "passport", "driver", "national id", "tax", "mother's maiden",
              "geographic location", "gps", "precise location", "health", "biometric", "citizenship")),
    ("medium", ("name", "username", "gender", "employer", "job title", "occupation", "education",
                "ip address", "device", "income", "nationality", "spoken language", "relationship")),
    ("low", ("email", "website", "social media", "avatar", "profile", "bio", "signup", "time zone")),
]

SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def classify(data_class: str) -> str:
    dc = data_class.lower()
    for sev, keywords in DATA_SEVERITY:
        if any(k in dc for k in keywords):
            return sev
    return "medium"


def worst(severities) -> str:
    best = "low"
    for s in severities:
        if SEVERITY_RANK[s] > SEVERITY_RANK[best]:
            best = s
    return best


@dataclass
class Breach:
    name: str
    title: str
    domain: str = ""
    date: str = ""                       # YYYY-MM-DD or YYYY
    count: int = 0                       # accounts affected
    data_classes: list[str] = field(default_factory=list)
    description: str = ""
    verified: bool = True
    sensitive: bool = False
    source: str = ""

    @property
    def year(self) -> int | None:
        m = re.match(r"(\d{4})", self.date or "")
        return int(m.group(1)) if m else None

    @property
    def severity(self) -> str:
        return worst([classify(d) for d in self.data_classes]) if self.data_classes else "medium"

    def exposes_passwords(self) -> bool:
        return any("password" in d.lower() or "credential" in d.lower() for d in self.data_classes)

    def exposes_financial(self) -> bool:
        return any(any(k in d.lower() for k in ("credit card", "bank", "cvv", "card number", "crypto"))
                   for d in self.data_classes)

    def to_dict(self) -> dict:
        return {"name": self.name, "title": self.title, "domain": self.domain, "date": self.date,
                "count": self.count, "data_classes": self.data_classes, "description": self.description,
                "verified": self.verified, "sensitive": self.sensitive, "severity": self.severity,
                "source": self.source}


@dataclass
class PasswordResult:
    checked: bool = False
    pwned: bool = False
    count: int = 0

    def to_dict(self):
        return {"checked": self.checked, "pwned": self.pwned, "count": self.count}


@dataclass
class ScanResult:
    email: str
    breaches: list[Breach]
    password: PasswordResult
    errors: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    scanned_at: str = ""

    def to_dict(self) -> dict:
        a = assess(self)
        return {"email": self.email, "scanned_at": self.scanned_at, "sources": self.sources,
                "errors": self.errors, "breaches": [b.to_dict() for b in self.breaches],
                "password": self.password.to_dict(), "assessment": a}


# --------------------------------------------------------------------------- risk scoring

SEV_POINTS = {"critical": 22, "high": 14, "medium": 8, "low": 4}


def assess(result: ScanResult) -> dict:
    breaches = result.breaches
    score = 0.0
    this_year = dt.date.today().year
    for b in breaches:
        pts = SEV_POINTS[b.severity]
        pts += 2 * max(0, len({classify(d) for d in b.data_classes}) - 1)  # breadth of data
        if b.year and this_year - b.year <= 2:
            pts *= 1.3                                                      # recent = worse
        if b.sensitive:
            pts += 4
        score += pts
    if result.password.pwned:
        score += 25
    score = min(100, round(score))

    pw_breaches = [b for b in breaches if b.exposes_passwords()]
    fin_breaches = [b for b in breaches if b.exposes_financial()]

    if not breaches and not result.password.pwned:
        level = "clear"
    elif score >= 70 or fin_breaches or (result.password.pwned and result.password.count > 0):
        level = "critical"
    elif score >= 40 or pw_breaches:
        level = "high"
    elif score >= 15:
        level = "medium"
    else:
        level = "low"

    # data categories exposed across all breaches, each with how many breaches had it
    cats: dict[str, dict] = {}
    for b in breaches:
        for d in b.data_classes:
            key = d.strip()
            if not key:
                continue
            c = cats.setdefault(key, {"name": key, "severity": classify(key), "breaches": 0})
            c["breaches"] += 1
    categories = sorted(cats.values(), key=lambda c: (-SEVERITY_RANK[c["severity"]], -c["breaches"], c["name"]))

    years = [b.year for b in breaches if b.year]
    return {
        "score": score,
        "level": level,
        "level_label": {"clear": "No known exposure", "low": "Low risk", "medium": "Medium risk",
                        "high": "High risk", "critical": "Critical risk"}[level],
        "breach_count": len(breaches),
        "password_breach_count": len(pw_breaches),
        "financial_breach_count": len(fin_breaches),
        "total_accounts": sum(b.count for b in breaches),
        "span": [min(years), max(years)] if years else None,
        "categories": categories,
        "password_pwned": result.password.pwned,
        "password_count": result.password.count,
        "actions": remediation(result, pw_breaches, fin_breaches),
    }


def remediation(result: ScanResult, pw_breaches, fin_breaches) -> list[dict]:
    a: list[dict] = []
    if result.password.pwned:
        a.append(("critical", "Stop using that password everywhere",
                  f"This password has appeared in {result.password.count:,} known breaches. "
                  "Change it on every account that uses it, starting with email and banking."))
    if pw_breaches:
        sites = ", ".join(sorted({b.title for b in pw_breaches})[:6])
        a.append(("critical", "Change passwords on the breached sites",
                  f"Your password was exposed in: {sites}. Change it there, and anywhere you reused it."))
    if result.breaches:
        a.append(("high", "Turn on two-factor authentication (2FA)",
                  "Enable 2FA on your email, banking and social accounts. An app like Aegis or "
                  "Authy beats SMS. 2FA blocks most attacks even when your password leaks."))
        a.append(("high", "Use a password manager with unique passwords",
                  "A manager (Bitwarden, KeePassXC, 1Password) gives every site its own strong "
                  "password, so one breach can't unlock the rest."))
    if fin_breaches:
        a.append(("high", "Watch your money",
                  "Financial data was exposed. Check bank and card statements, set up transaction "
                  "alerts, and consider a credit freeze."))
    high_cats = {classify(d) for b in result.breaches for d in b.data_classes}
    if "high" in high_cats or "critical" in high_cats:
        a.append(("medium", "Expect targeted phishing and SIM-swap attempts",
                  "Personal details are out there, so scam calls/texts may quote real info to sound "
                  "legit. Never share codes; be wary of urgent 'security' messages. Consider a SIM/port-out PIN."))
    a.append(("low", "Set up ongoing monitoring",
              "Re-run BreachLens now and then, and subscribe to free breach alerts at "
              "haveibeenpwned.com/NotifyMe so you hear about new leaks fast."))
    if not result.breaches and not result.password.pwned:
        a = [("low", "Keep it that way",
              "No known exposure. Still use unique passwords and 2FA, and check again periodically — "
              "new breaches surface all the time.")]
    return [{"severity": s, "title": t, "detail": d} for s, t, d in a]


# --------------------------------------------------------------------------- HTTP

def http_get(url: str, headers: dict | None = None, timeout: float = 20):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, r.read().decode("utf-8", "replace")


# --------------------------------------------------------------------------- password check (k-anonymity)

def password_prefix_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_pwned_range(body: str, suffix: str) -> int:
    """Given the Pwned Passwords range response, return how many times our suffix appears."""
    for line in body.splitlines():
        sfx, _, cnt = line.strip().partition(":")
        if sfx.upper() == suffix:
            try:
                return int(cnt.strip().replace(",", ""))
            except ValueError:
                return 0
    return 0


def check_password(password: str, getter=None) -> PasswordResult:
    """Check a password against Pwned Passwords WITHOUT sending it.

    Only the first 5 chars of its SHA-1 hash are sent; the rest is matched locally.
    """
    getter = getter or (lambda prefix: http_get(
        f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true"})[1])
    prefix, suffix = password_prefix_suffix(password)
    body = getter(prefix)
    count = parse_pwned_range(body, suffix)
    return PasswordResult(checked=True, pwned=count > 0, count=count)


# --------------------------------------------------------------------------- breach sources

class SourceError(Exception):
    pass


def _norm_data_classes(values) -> list[str]:
    out, seen = [], set()
    for v in values or []:
        for part in re.split(r"[;,]", str(v)):
            p = re.sub(r"\s+", " ", part).strip()
            if p and p.lower() not in seen:
                seen.add(p.lower())
                out.append(p)
    return out


class XposedOrNot:
    """Free breach lookup, no API key required. https://xposedornot.com"""
    name = "XposedOrNot"

    def __init__(self, getter=http_get):
        self._get = getter

    def lookup(self, email: str) -> list[Breach]:
        url = "https://api.xposedornot.com/v1/breach-analytics?email=" + urllib.parse.quote(email)
        try:
            status, body = self._get(url)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return []
            raise SourceError(f"XposedOrNot HTTP {e.code}")
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise SourceError(f"XposedOrNot unreachable: {getattr(e, 'reason', e)}")
        try:
            data = json.loads(body)
        except ValueError:
            raise SourceError("XposedOrNot returned invalid JSON")
        if isinstance(data, dict) and data.get("Error") and "not found" in str(data["Error"]).lower():
            return []
        return self.parse(data)

    @staticmethod
    def parse(data: dict) -> list[Breach]:
        breaches: list[Breach] = []
        details = (((data or {}).get("ExposedBreaches") or {}).get("breaches_details")) or []
        for d in details:
            if not isinstance(d, dict):
                continue
            classes = d.get("xposed_data") or d.get("xposedData") or ""
            try:
                count = int(str(d.get("xposed_records") or 0).replace(",", "") or 0)
            except ValueError:
                count = 0
            breaches.append(Breach(
                name=str(d.get("breach") or d.get("name") or "Unknown"),
                title=str(d.get("breach") or d.get("name") or "Unknown"),
                domain=str(d.get("domain") or ""),
                date=str(d.get("xposed_date") or d.get("breach_date") or ""),
                count=count,
                data_classes=_norm_data_classes([classes]),
                description=str(d.get("details") or ""),
                verified=str(d.get("verified", "Yes")).lower() not in ("no", "false", "0"),
                sensitive=str(d.get("sensitive", "No")).lower() in ("yes", "true", "1"),
                source="XposedOrNot"))
        return breaches


class HaveIBeenPwned:
    """Authoritative breach lookup. Email search needs an API key (~$4/mo)."""
    name = "Have I Been Pwned"

    def __init__(self, api_key: str, getter=http_get):
        self.api_key = api_key
        self._get = getter

    def lookup(self, email: str) -> list[Breach]:
        url = ("https://haveibeenpwned.com/api/v3/breachedaccount/"
               + urllib.parse.quote(email) + "?truncateResponse=false")
        try:
            status, body = self._get(url, {"hibp-api-key": self.api_key})
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return []
            if e.code == 401:
                raise SourceError("HIBP rejected the API key")
            if e.code == 429:
                raise SourceError("HIBP rate limit hit; wait a moment and retry")
            raise SourceError(f"HIBP HTTP {e.code}")
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise SourceError(f"HIBP unreachable: {getattr(e, 'reason', e)}")
        try:
            data = json.loads(body)
        except ValueError:
            raise SourceError("HIBP returned invalid JSON")
        return self.parse(data)

    @staticmethod
    def parse(data) -> list[Breach]:
        out = []
        for d in data or []:
            if not isinstance(d, dict):
                continue
            out.append(Breach(
                name=str(d.get("Name") or ""),
                title=str(d.get("Title") or d.get("Name") or ""),
                domain=str(d.get("Domain") or ""),
                date=str(d.get("BreachDate") or ""),
                count=int(d.get("PwnCount") or 0),
                data_classes=_norm_data_classes(d.get("DataClasses")),
                description=re.sub(r"<[^>]+>", "", str(d.get("Description") or "")),
                verified=bool(d.get("IsVerified", True)),
                sensitive=bool(d.get("IsSensitive", False)),
                source="Have I Been Pwned"))
        return out


def get_source(name: str, hibp_key: str | None, getter=http_get):
    if name == "hibp" or (name == "auto" and hibp_key):
        if not hibp_key:
            die("HIBP needs an API key. Run: breachlens.py set-key   (or use --source xposedornot)")
        return HaveIBeenPwned(hibp_key, getter)
    return XposedOrNot(getter)


def scan_email(email: str, source, password: str | None = None,
               pw_getter=None) -> ScanResult:
    errors: list[str] = []
    breaches: list[Breach] = []
    try:
        breaches = source.lookup(email)
    except SourceError as e:
        errors.append(str(e))
    breaches.sort(key=lambda b: (-SEVERITY_RANK[b.severity], -(b.year or 0), b.title.lower()))
    pw = PasswordResult()
    if password:
        try:
            pw = check_password(password, pw_getter)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as e:
            errors.append(f"Password check failed: {getattr(e, 'reason', e)}")
    return ScanResult(email=email, breaches=breaches, password=pw, errors=errors,
                      sources=[source.name], scanned_at=dt.datetime.now().strftime("%Y-%m-%d %H:%M"))


# --------------------------------------------------------------------------- terminal report

LEVEL_COLOR = {"clear": green, "low": green, "medium": yellow, "high": red, "critical": red}


def print_report(result: ScanResult):
    a = assess(result)
    color = LEVEL_COLOR[a["level"]]
    print()
    print(bold(" BreachLens ") + dim("· " + result.scanned_at + " · " + ", ".join(result.sources)))
    print(" " + bold(result.email))
    print()
    badge = f"  {a['level_label'].upper()}  "
    print(" " + color(bold(badge)) + "   " + dim(f"exposure score {a['score']}/100"))
    if a["breach_count"]:
        span = f" ({a['span'][0]}–{a['span'][1]})" if a["span"] else ""
        print(f"   {a['breach_count']} breach(es){span} · {a['total_accounts']:,} accounts exposed in total")
        if a["password_breach_count"]:
            print(red(f"   ⚠ passwords exposed in {a['password_breach_count']} breach(es)"))
    else:
        print(green("   No known breaches for this email."))
    if result.password.checked:
        if result.password.pwned:
            print(red(f"   ⚠ the password you checked has been seen {result.password.count:,} times in breaches"))
        else:
            print(green("   ✓ the password you checked was not found in any known breach"))

    if result.breaches:
        print()
        print(dim(" BREACHES  (worst first)"))
        for b in result.breaches:
            sc = {"critical": red, "high": red, "medium": yellow, "low": dim}[b.severity]
            head = f"  {sc('●')} {bold(b.title)}"
            meta = dim(f"{b.date or '?'} · {b.count:,} accounts" if b.count else (b.date or "?"))
            print(f"{head}  {meta}")
            if b.data_classes:
                shown = ", ".join(b.data_classes[:8]) + (" …" if len(b.data_classes) > 8 else "")
                print(f"      {dim('exposed:')} {shown}")

    if a["categories"]:
        print()
        print(dim(" YOUR DATA THAT'S OUT THERE"))
        for c in a["categories"][:12]:
            sc = {"critical": red, "high": yellow, "medium": cyan, "low": dim}[c["severity"]]
            print(f"  {sc('■')} {c['name']} " + dim(f"({c['breaches']})"))

    print()
    print(dim(" WHAT TO DO"))
    for i, act in enumerate(a["actions"], 1):
        mark = {"critical": red("!"), "high": yellow("!"), "medium": cyan("•"), "low": dim("•")}[act["severity"]]
        print(f"  {mark} {bold(act['title'])}")
        print(dim(f"      {act['detail']}"))
    if result.errors:
        print()
        for e in result.errors:
            print(yellow("  note: " + e))
    print()


# --------------------------------------------------------------------------- HTML report

REPORT_CSS = """
:root{--bg:#0b0f15;--panel:#121923;--panel2:#18212e;--line:#223042;--text:#e6edf4;--muted:#8fa0b4;
--faint:#5f6f82;--green:#35d08b;--greenbg:rgba(53,208,139,.12);--amber:#f5b942;--amberbg:rgba(245,185,66,.12);
--red:#ff5b6a;--redbg:rgba(255,91,106,.12);--blue:#5aa9ff;--bluebg:rgba(90,169,255,.1);
--mono:ui-monospace,"JetBrains Mono",Menlo,Consolas,"DejaVu Sans Mono",monospace;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
.wrap{max-width:860px;margin:0 auto;padding:28px 22px 60px}
.brand{display:flex;align-items:center;gap:10px;font:800 18px/1 var(--sans);letter-spacing:.02em;margin-bottom:4px}
.brand .lens{color:var(--blue)}
.sub{color:var(--muted);font-size:13px;margin-bottom:22px}
.hero{display:flex;gap:22px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px 24px;margin-bottom:18px;flex-wrap:wrap}
.gauge{--p:0;width:116px;height:116px;border-radius:50%;flex:none;display:grid;place-items:center;
background:conic-gradient(var(--gc) calc(var(--p)*1%),var(--line) 0)}
.gauge .inner{width:92px;height:92px;border-radius:50%;background:var(--panel);display:grid;place-items:center;text-align:center}
.gauge .num{font:800 30px/1 var(--mono)}
.gauge .lbl{font-size:10px;color:var(--muted);letter-spacing:.14em;text-transform:uppercase;margin-top:3px}
.heroinfo{flex:1;min-width:220px}
.email{font:600 17px/1.3 var(--mono);word-break:break-all}
.level{display:inline-block;font:700 13px var(--sans);padding:5px 12px;border-radius:999px;margin:8px 0 6px}
.lv-clear,.lv-low{color:var(--green);background:var(--greenbg)}
.lv-medium{color:var(--amber);background:var(--amberbg)}
.lv-high,.lv-critical{color:var(--red);background:var(--redbg)}
.summary{color:var(--muted);font-size:14px}
.summary b{color:var(--text)}
.alert{display:flex;gap:10px;align-items:flex-start;border-radius:12px;padding:12px 15px;margin-bottom:10px;font-size:14px}
.alert.red{background:var(--redbg);border:1px solid rgba(255,91,106,.35);color:#ffd4d9}
.alert.red b{color:#fff}
.alert.green{background:var(--greenbg);border:1px solid rgba(53,208,139,.3);color:#c7f4df}
h2{font:700 12px var(--sans);letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin:26px 0 12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.breach{display:grid;grid-template-columns:auto 1fr auto;gap:4px 14px;padding:14px 18px;border-bottom:1px solid var(--line)}
.breach:last-child{border-bottom:0}
.sevdot{grid-row:1/3;width:11px;height:11px;border-radius:50%;margin-top:6px}
.sv-critical{background:var(--red)} .sv-high{background:#ff8a3d} .sv-medium{background:var(--amber)} .sv-low{background:var(--faint)}
.bt{font-weight:700} .bmeta{color:var(--faint);font:12px var(--mono);text-align:right;white-space:nowrap}
.bclasses{grid-column:2/4;display:flex;flex-wrap:wrap;gap:6px;margin-top:7px}
.pill{font:11px var(--sans);padding:3px 9px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);color:var(--muted)}
.pill.critical{color:var(--red);border-color:rgba(255,91,106,.4);background:var(--redbg)}
.pill.high{color:#ffb27a;border-color:rgba(255,138,61,.35);background:rgba(255,138,61,.1)}
.pill.medium{color:var(--amber);border-color:rgba(245,185,66,.3);background:var(--amberbg)}
.bdesc{grid-column:2/4;color:var(--muted);font-size:13px;margin-top:8px}
.cats{display:flex;flex-wrap:wrap;gap:8px}
.cat{display:flex;align-items:center;gap:8px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:8px 12px;font-size:13px}
.cat .sq{width:9px;height:9px;border-radius:2px}
.cat .n{color:var(--faint);font:11px var(--mono)}
.actions{display:flex;flex-direction:column;gap:10px}
.act{display:grid;grid-template-columns:auto 1fr;gap:12px;background:var(--panel);border:1px solid var(--line);border-left-width:3px;border-radius:12px;padding:14px 16px}
.act.critical{border-left-color:var(--red)} .act.high{border-left-color:var(--amber)}
.act.medium{border-left-color:var(--blue)} .act.low{border-left-color:var(--faint)}
.act .ic{width:26px;height:26px;border-radius:7px;display:grid;place-items:center;font-weight:800;font-size:14px}
.act.critical .ic,.act.high .ic{background:var(--redbg);color:var(--red)}
.act.medium .ic{background:var(--bluebg);color:var(--blue)} .act.low .ic{background:var(--panel2);color:var(--muted)}
.act .t{font-weight:700;margin-bottom:2px} .act .d{color:var(--muted);font-size:13.5px}
.note{color:var(--amber);font-size:13px;margin-top:10px}
footer{margin-top:34px;color:var(--faint);font-size:12px;text-align:center;line-height:1.7}
.empty{padding:26px;text-align:center;color:var(--muted)}
@media (max-width:560px){.hero{justify-content:center;text-align:center}.breach{grid-template-columns:auto 1fr}.bmeta{grid-column:2;text-align:left;margin-top:2px}}
"""

GAUGE_COLOR = {"clear": "var(--green)", "low": "var(--green)", "medium": "var(--amber)",
               "high": "var(--red)", "critical": "var(--red)"}


def render_report(result: ScanResult, standalone: bool = True) -> str:
    a = assess(result)
    lvl = a["level"]
    p = ['<div class="brand"><span class="lens">◎</span> BreachLens</div>',
         f'<div class="sub">Exposure report · {esc(result.scanned_at)} · source: {esc(", ".join(result.sources))}</div>']

    p.append(f'<div class="hero"><div class="gauge" style="--p:{a["score"]};--gc:{GAUGE_COLOR[lvl]}">'
             f'<div class="inner"><div class="num">{a["score"]}</div><div class="lbl">exposure</div></div></div>'
             f'<div class="heroinfo"><div class="email">{esc(result.email)}</div>'
             f'<div class="level lv-{lvl}">{esc(a["level_label"])}</div>')
    if a["breach_count"]:
        span = f' from {a["span"][0]} to {a["span"][1]}' if a["span"] else ""
        p.append(f'<div class="summary">Found in <b>{a["breach_count"]}</b> breach'
                 f'{"es" if a["breach_count"] != 1 else ""}{esc(span)}, '
                 f'exposing <b>{a["total_accounts"]:,}</b> accounts in total.</div>')
    else:
        p.append('<div class="summary">No known breaches for this email address.</div>')
    p.append('</div></div>')

    if a["password_pwned"]:
        p.append(f'<div class="alert red"><b>⚠</b><div>The password you checked has appeared '
                 f'<b>{a["password_count"]:,}</b> times in known breaches. Change it everywhere you use it.</div></div>')
    elif result.password.checked:
        p.append('<div class="alert green"><b>✓</b><div>The password you checked was not found in any known breach. '
                 '(It was never sent — only the first 5 characters of its hash were.)</div></div>')
    if a["password_breach_count"]:
        p.append(f'<div class="alert red"><b>⚠</b><div>Your <b>password</b> was among the data exposed in '
                 f'<b>{a["password_breach_count"]}</b> of these breaches.</div></div>')

    if result.breaches:
        p.append('<h2>Breaches, worst first</h2><div class="card">')
        for b in result.breaches:
            meta = esc(b.date or "date unknown")
            if b.count:
                meta += f' · {b.count:,} accounts'
            p.append(f'<div class="breach"><span class="sevdot sv-{b.severity}"></span>'
                     f'<div class="bt">{esc(b.title)}{" 🔒" if b.sensitive else ""}</div>'
                     f'<div class="bmeta">{meta}</div>')
            if b.data_classes:
                pills = "".join(f'<span class="pill {classify(d)}">{esc(d)}</span>' for d in b.data_classes[:12])
                p.append(f'<div class="bclasses">{pills}</div>')
            if b.description and standalone:
                desc = b.description[:260] + ("…" if len(b.description) > 260 else "")
                p.append(f'<div class="bdesc">{esc(desc)}</div>')
            p.append('</div>')
        p.append('</div>')

    if a["categories"]:
        p.append('<h2>Your data that\'s out there</h2><div class="cats">')
        sqcolor = {"critical": "var(--red)", "high": "#ff8a3d", "medium": "var(--amber)", "low": "var(--faint)"}
        for c in a["categories"]:
            p.append(f'<div class="cat"><span class="sq" style="background:{sqcolor[c["severity"]]}"></span>'
                     f'{esc(c["name"])} <span class="n">{c["breaches"]}×</span></div>')
        p.append('</div>')

    p.append('<h2>What to do now</h2><div class="actions">')
    icons = {"critical": "!", "high": "!", "medium": "2", "low": "✓"}
    for act in a["actions"]:
        p.append(f'<div class="act {act["severity"]}"><div class="ic">{icons[act["severity"]]}</div>'
                 f'<div><div class="t">{esc(act["title"])}</div><div class="d">{esc(act["detail"])}</div></div></div>')
    p.append('</div>')

    for e in result.errors:
        p.append(f'<div class="note">Note: {esc(e)}</div>')

    body = "\n".join(p)
    if not standalone:
        return body
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>BreachLens report · {esc(result.email)}</title><style>{REPORT_CSS}</style></head>'
            f'<body><div class="wrap">{body}'
            f'<footer>Generated by BreachLens {VERSION}. Breach data from public breach-notification '
            f'services; absence of a breach is not proof of safety. For your own accounts only.</footer>'
            f'</div></body></html>')


# --------------------------------------------------------------------------- config

def config_path() -> str:
    base = os.environ.get("BREACHLENS_DIR") or os.path.join(
        os.path.expanduser("~"), ".config", "breachlens")
    return os.path.join(base, "config.json")


def load_config() -> dict:
    try:
        with open(config_path(), encoding="utf-8") as f:
            c = json.load(f)
            return c if isinstance(c, dict) else {}
    except (OSError, ValueError):
        return {}


def save_key(key: str):
    path = config_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    cfg = load_config()
    cfg["hibp_api_key"] = key
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def hibp_key() -> str | None:
    return os.environ.get("HIBP_API_KEY") or load_config().get("hibp_api_key")


# --------------------------------------------------------------------------- web UI

def make_handler(token: str, hibp: str | None, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "BreachLens"
        sys_version = ""

        def log_message(self, *a):
            pass

        def _host_ok(self):
            return (self.headers.get("Host") or "").lower() in allowed_hosts

        def _send(self, code, body, ctype="application/json", nonce=None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            script = f"'nonce-{nonce}'" if nonce else "'none'"
            self.send_header("Content-Security-Policy",
                             f"default-src 'none'; script-src {script}; style-src 'unsafe-inline'; "
                             "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "bad host"})
            if urllib.parse.urlsplit(self.path).path != "/":
                return self._send(404, {"error": "not found"})
            nonce = secrets.token_urlsafe(16)
            page = WEB_HTML.replace("__TOKEN__", token).replace("__NONCE__", nonce).replace("__CSS__", REPORT_CSS)
            self._send(200, page.encode(), "text/html; charset=utf-8", nonce=nonce)

        def do_POST(self):
            if not self._host_ok():
                return self._send(403, {"error": "bad host"})
            if not secrets.compare_digest(self.headers.get("X-BL-Token", "").encode(), token.encode()):
                return self._send(401, {"error": "unauthorized"})
            if urllib.parse.urlsplit(self.path).path != "/api/check":
                return self._send(404, {"error": "not found"})
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return self._send(415, {"error": "JSON only"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2048:
                return self._send(413, {"error": "too large"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
                assert isinstance(body, dict)
            except (ValueError, AssertionError):
                return self._send(400, {"error": "bad JSON"})
            email = str(body.get("email", "")).strip()
            password = body.get("password") or None
            if not EMAIL_RE.match(email):
                return self._send(400, {"error": "Enter a valid email address"})
            source = get_source("auto", hibp)
            result = scan_email(email, source, password if isinstance(password, str) else None)
            self._send(200, {"html": render_report(result, standalone=False),
                             "data": result.to_dict()})

    return Handler


def cmd_serve(args):
    token = secrets.token_hex(16)
    key = hibp_key()

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    try:
        server = Server((args.host, args.port), make_handler(token, key, args.port))
    except OSError as e:
        die(f"could not start on {args.host}:{args.port} ({e.strerror}). Try --port 8089")
    url = f"http://127.0.0.1:{args.port}/"
    print(bold(green("◎ BreachLens")) + dim(f" v{VERSION} · web UI"))
    print(green("  Open: ") + bold(url))
    print(dim("  Source: " + ("Have I Been Pwned (key set)" if key else "XposedOrNot (free). Set a HIBP key for more: breachlens.py set-key")))
    print(dim("  Private: binds to localhost only. Ctrl+C to stop."))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


# --------------------------------------------------------------------------- commands

def _resolve_password(args) -> str | None:
    if getattr(args, "check_password", False):
        pw = getpass.getpass("Password to check (hidden, never sent): ")
        if not pw:
            die("no password entered")
        return pw
    return None


def cmd_check(args):
    email = args.email.strip()
    if not EMAIL_RE.match(email):
        die(f"'{email}' is not a valid email address")
    source = get_source(args.source, hibp_key())
    result = scan_email(email, source, _resolve_password(args))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_report(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(render_report(result))
        print(dim(f"HTML report written to {args.output}"))


def cmd_report(args):
    email = args.email.strip()
    if not EMAIL_RE.match(email):
        die(f"'{email}' is not a valid email address")
    source = get_source(args.source, hibp_key())
    result = scan_email(email, source, _resolve_password(args))
    out = args.output or f"breachlens-{re.sub(r'[^a-z0-9]+', '_', email.lower())}.html"
    with open(out, "w", encoding="utf-8") as f:
        f.write(render_report(result))
    print(green("✓ report written to ") + bold(out))
    a = assess(result)
    print(dim(f"  {a['level_label']} · {a['breach_count']} breach(es) · exposure {a['score']}/100"))


def cmd_password(args):
    pw = getpass.getpass("Password to check (hidden, never sent): ")
    if not pw:
        die("no password entered")
    try:
        res = check_password(pw)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as e:
        die(f"could not reach Pwned Passwords: {getattr(e, 'reason', e)}")
    print()
    if res.pwned:
        print(red(bold(f"  ✗ Found {res.count:,} times in known breaches.")))
        print("  Don't use this password. Change it anywhere you use it, and pick a unique one.")
    else:
        print(green(bold("  ✓ Not found in any known breach.")))
        print("  Good — but still use a unique password per site and turn on 2FA.")
    print(dim("  (Your password was never sent — only the first 5 characters of its SHA-1 hash.)"))
    print()


def cmd_set_key(args):
    key = (args.key or getpass.getpass("HIBP API key (hidden): ")).strip()
    if not HIBP_KEY_RE.match(key):
        die("that doesn't look like a HIBP API key (32 hex characters). Get one at haveibeenpwned.com/API/Key")
    save_key(key)
    print(green("✓ saved to ") + config_path())
    print(dim("  BreachLens will now use Have I Been Pwned for email lookups."))


def cmd_demo(args):
    result = demo_result()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(render_report(result))
        print(green("✓ demo report written to ") + bold(args.output))
    else:
        print_report(result)
        print(dim(" This is simulated data. Try:  python3 breachlens.py demo -o demo.html"))


# --------------------------------------------------------------------------- demo data

def demo_result() -> ScanResult:
    breaches = [
        Breach("Collection1", "Collection #1", "", "2019-01-07", 772904991,
               ["Email addresses", "Passwords"], "A large set of credential-stuffing combolists.",
               True, False, "demo"),
        Breach("LinkedIn", "LinkedIn", "linkedin.com", "2012-05-05", 164611595,
               ["Email addresses", "Passwords"],
               "In 2012 LinkedIn was breached and 164M accounts with SHA1 passwords were exposed.",
               True, False, "demo"),
        Breach("Dropbox", "Dropbox", "dropbox.com", "2012-07-01", 68648009,
               ["Email addresses", "Passwords"], "Dropbox credentials exposed in mid-2012.",
               True, False, "demo"),
        Breach("Canva", "Canva", "canva.com", "2019-05-24", 137272116,
               ["Email addresses", "Geographic locations", "Names", "Usernames", "Passwords"],
               "Design site Canva exposed 137M accounts.", True, False, "demo"),
        Breach("Adobe", "Adobe", "adobe.com", "2013-10-04", 152445165,
               ["Email addresses", "Password hints", "Passwords", "Usernames"],
               "Adobe's 2013 breach exposed 153M accounts with poorly encrypted passwords.",
               True, False, "demo"),
        Breach("Twitter200M", "Twitter (200M)", "twitter.com", "2023-01-01", 211524284,
               ["Email addresses", "Names", "Usernames", "Phone numbers"],
               "A scraped set linking Twitter handles to emails and some phone numbers.",
               True, False, "demo"),
    ]
    return ScanResult(email="demo.user@example.com", breaches=sorted(
        breaches, key=lambda b: (-SEVERITY_RANK[b.severity], -(b.year or 0))),
        password=PasswordResult(checked=True, pwned=True, count=3730471),
        errors=[], sources=["demo"], scanned_at=dt.datetime.now().strftime("%Y-%m-%d %H:%M"))


# --------------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="breachlens.py",
        description="Check whether your email and passwords have leaked in data breaches. "
                    "Use only on accounts you own or are allowed to check.")
    p.add_argument("--version", action="version", version=f"BreachLens {VERSION}")
    p.add_argument("--no-color", action="store_true")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    def src(sp):
        sp.add_argument("--source", choices=["auto", "xposedornot", "hibp"], default="auto",
                        help="breach source (auto uses HIBP if a key is set, else XposedOrNot)")

    c = sub.add_parser("check", help="check an email and print a report")
    c.add_argument("email")
    src(c)
    c.add_argument("--check-password", action="store_true", help="also check a password (prompted, hidden)")
    c.add_argument("-o", "--output", help="also write an HTML report to this file")
    c.add_argument("--json", action="store_true", help="output raw JSON instead of a table")

    r = sub.add_parser("report", help="write an HTML report for an email")
    r.add_argument("email")
    src(r)
    r.add_argument("--check-password", action="store_true")
    r.add_argument("-o", "--output", help="output file (default breachlens-<email>.html)")

    sub.add_parser("password", help="check if a password has been breached (hidden input)")

    s = sub.add_parser("serve", help="run the local web UI")
    s.add_argument("--port", type=int, default=8088)
    s.add_argument("--host", default="127.0.0.1", help=argparse.SUPPRESS)

    d = sub.add_parser("demo", help="show a sample report (simulated data, no network)")
    d.add_argument("-o", "--output", help="write the demo report to an HTML file")

    k = sub.add_parser("set-key", help="save a Have I Been Pwned API key")
    k.add_argument("--key", help=argparse.SUPPRESS)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "no_color", False):
        Color.on = False
    if not args.cmd:
        parser.print_help()
        print("\nTry:  python3 breachlens.py demo")
        return
    handlers = {"check": cmd_check, "report": cmd_report, "password": cmd_password,
                "serve": cmd_serve, "demo": cmd_demo, "set-key": cmd_set_key}
    try:
        handlers[args.cmd](args)
    except KeyboardInterrupt:
        print()


WEB_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BreachLens</title><style>__CSS__
.search{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px;margin-bottom:18px}
.search h1{font:800 20px var(--sans);margin:0 0 4px;display:flex;align-items:center;gap:9px}
.search h1 .lens{color:var(--blue)}
.search p{color:var(--muted);font-size:13px;margin:0 0 16px}
.row{display:flex;gap:10px;flex-wrap:wrap}
.row input[type=email],.row input[type=password]{flex:1;min-width:200px;background:var(--bg);border:1px solid var(--line);
border-radius:10px;color:var(--text);padding:12px 14px;font:15px var(--mono)}
.row input:focus{outline:none;border-color:var(--blue)}
button{background:var(--blue);color:#03101f;border:0;border-radius:10px;padding:12px 22px;font:700 15px var(--sans);cursor:pointer}
button:hover{filter:brightness(1.08)} button:disabled{opacity:.6;cursor:default}
.opt{display:flex;align-items:center;gap:8px;margin-top:12px;color:var(--muted);font-size:13px}
.opt input{accent-color:var(--blue)}
.pwrow{margin-top:10px;display:none} .pwrow.show{display:flex}
.hint{color:var(--faint);font-size:12px;margin-top:10px}
.loading{text-align:center;color:var(--muted);padding:30px}
.spin{width:30px;height:30px;border:3px solid var(--line);border-top-color:var(--blue);border-radius:50%;animation:s .8s linear infinite;margin:0 auto 12px}
@keyframes s{to{transform:rotate(360deg)}}
.err{background:var(--redbg);border:1px solid rgba(255,91,106,.35);color:#ffd4d9;border-radius:10px;padding:12px 15px;margin-bottom:16px}
</style></head>
<body><div class="wrap">
<div class="search">
  <h1><span class="lens">◎</span> BreachLens</h1>
  <p>See which breaches exposed your email, and what to do about it. For your own accounts only.</p>
  <div class="row">
    <input id="email" type="email" placeholder="you@example.com" autocomplete="off" spellcheck="false">
    <button id="go">Check</button>
  </div>
  <label class="opt"><input type="checkbox" id="pwtoggle"> also check a password (it's never sent — only a hash prefix)</label>
  <div class="row pwrow" id="pwrow"><input id="password" type="password" placeholder="password to check" autocomplete="off"></div>
  <div class="hint">Binds to localhost. Your email is sent to the breach service you configured; your password is not.</div>
</div>
<div id="out"></div>
<footer>BreachLens __VER__ · breach data from public breach-notification services · for your own accounts only</footer>
</div>
<script nonce="__NONCE__">
"use strict";
const TOKEN="__TOKEN__", $=s=>document.querySelector(s);
const out=$("#out");
$("#pwtoggle").addEventListener("change",e=>{$("#pwrow").classList.toggle("show",e.target.checked);if(!e.target.checked)$("#password").value="";});
async function run(){
  const email=$("#email").value.trim();
  if(!email){out.innerHTML='<div class="err">Enter an email address.</div>';return;}
  const body={email};
  if($("#pwtoggle").checked && $("#password").value) body.password=$("#password").value;
  $("#go").disabled=true;
  out.innerHTML='<div class="loading"><div class="spin"></div>Checking breach databases…</div>';
  try{
    const r=await fetch("/api/check",{method:"POST",headers:{"Content-Type":"application/json","X-BL-Token":TOKEN},body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok){out.innerHTML='<div class="err">'+(d.error||("Error "+r.status))+'</div>';}
    else{out.innerHTML=d.html;}          // server-built, fully escaped; no scripts in fragment
  }catch(e){out.innerHTML='<div class="err">Could not run the check: '+e.message+'</div>';}
  $("#go").disabled=false;
}
$("#go").addEventListener("click",run);
$("#email").addEventListener("keydown",e=>{if(e.key==="Enter")run();});
$("#password").addEventListener("keydown",e=>{if(e.key==="Enter")run();});
</script>
</body></html>
""".replace("__VER__", VERSION)


if __name__ == "__main__":
    main()
