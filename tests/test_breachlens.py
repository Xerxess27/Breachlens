import hashlib
import importlib.util
import json
import os
import sys

spec = importlib.util.spec_from_file_location(
    "bl", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "breachlens.py"))
bl = importlib.util.module_from_spec(spec)
sys.modules["bl"] = bl
spec.loader.exec_module(bl)

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails += 1


# ---------------------------------------------------------------- password k-anonymity
# The crux: the real password must never leave the machine. We capture what the
# network getter receives and assert it is only the 5-char hash prefix.
def test_password_privacy():
    pw = "password"                       # SHA1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    full = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = full[:5], full[5:]
    sent = {}

    def getter(p):
        sent["prefix"] = p
        # a realistic range response: other suffixes + ours with a count
        return f"00000000000000000000000000000000001:5\r\n{suffix}:99999\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2"

    res = bl.check_password(pw, getter)
    check(sent["prefix"] == prefix, f"only the 5-char hash prefix is sent ({sent['prefix']})")
    check(pw not in str(sent) and suffix not in str(sent.get("prefix", "")), "neither the password nor its full hash is sent")
    check(len(sent["prefix"]) == 5, "exactly 5 characters are sent")
    check(res.pwned and res.count == 99999, f"correctly parses the breach count ({res.count})")

    safe = bl.check_password("a-truly-unique-passphrase", lambda p: "ABC:1\r\nDEF:2")
    check(safe.checked and not safe.pwned and safe.count == 0, "a password not in the range reads as safe")

    # count parsing tolerates the comma form some mirrors use
    pfx, sfx = bl.password_prefix_suffix("hunter2")
    check(bl.parse_pwned_range(f"{sfx}:1,234", sfx) == 1234, "parses comma-form counts")


# ---------------------------------------------------------------- XposedOrNot parsing
def test_xposedornot():
    payload = {"ExposedBreaches": {"breaches_details": [
        {"breach": "LinkedIn", "domain": "linkedin.com", "xposed_date": "2012",
         "xposed_records": "164,611,595", "xposed_data": "Email addresses;Passwords",
         "details": "LinkedIn breach"},
        {"breach": "Canva", "domain": "canva.com", "xposed_date": "2019",
         "xposed_records": 137272116, "xposed_data": "Email addresses;Names;Geographic locations"},
    ]}}

    def getter(url, headers=None):
        check("breach-analytics" in url and "a%40b.com" in url, "XposedOrNot builds the analytics URL with an encoded email")
        return 200, json.dumps(payload)

    src = bl.XposedOrNot(getter)
    breaches = src.lookup("a@b.com")
    check(len(breaches) == 2, f"parses both breaches ({len(breaches)})")
    li = next(b for b in breaches if b.name == "LinkedIn")
    check(li.count == 164611595, "parses the comma-formatted record count")
    check(li.data_classes == ["Email addresses", "Passwords"], f"splits data classes ({li.data_classes})")
    check(li.exposes_passwords() and li.severity == "critical", "a password breach is rated critical")
    canva = next(b for b in breaches if b.name == "Canva")
    check(not canva.exposes_passwords() and canva.severity == "high", "geolocation (no password) rates high")

    # a 404 / "not found" means a clean email, not an error
    import urllib.error
    def nf(url, headers=None):
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)
    check(bl.XposedOrNot(nf).lookup("x@y.com") == [], "404 is treated as 'no breaches'")

    def errjson(url, headers=None):
        return 200, json.dumps({"Error": "Not found"})
    check(bl.XposedOrNot(errjson).lookup("x@y.com") == [], "'Not found' JSON is treated as clean")


# ---------------------------------------------------------------- HIBP parsing
def test_hibp():
    payload = [
        {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
         "PwnCount": 152445165, "DataClasses": ["Email addresses", "Password hints", "Passwords"],
         "Description": "<p>Adobe <b>breach</b></p>", "IsVerified": True, "IsSensitive": False},
    ]
    sent = {}

    def getter(url, headers=None):
        sent["headers"] = headers or {}
        return 200, json.dumps(payload)

    src = bl.HaveIBeenPwned("deadbeef" * 4, getter)
    breaches = src.lookup("a@b.com")
    check(sent["headers"].get("hibp-api-key") == "deadbeef" * 4, "HIBP sends the API key header")
    check(len(breaches) == 1 and breaches[0].count == 152445165, "parses the HIBP breach")
    check(breaches[0].description == "Adobe breach", "strips HTML from the description")
    check(breaches[0].data_classes[0] == "Email addresses", "keeps data classes")

    import urllib.error
    def unauth(url, headers=None):
        raise urllib.error.HTTPError(url, 401, "no", {}, None)
    try:
        bl.HaveIBeenPwned("bad", unauth).lookup("a@b.com")
        check(False, "a 401 raises SourceError")
    except bl.SourceError as e:
        check("key" in str(e).lower(), "a 401 explains the key was rejected")


# ---------------------------------------------------------------- risk scoring
def test_scoring():
    def mk(name, classes, date, sensitive=False):
        return bl.Breach(name, name, "", date, 1000, classes, "", True, sensitive, "t")

    # clean
    clean = bl.ScanResult("a@b.com", [], bl.PasswordResult())
    ac = bl.assess(clean)
    check(ac["level"] == "clear" and ac["score"] == 0, "no breaches => clear, score 0")

    # a single old low-severity breach => low
    low = bl.ScanResult("a@b.com", [mk("Forum", ["Email addresses"], "2011")], bl.PasswordResult())
    check(bl.assess(low)["level"] == "low", f"one email-only breach => low ({bl.assess(low)['level']})")

    # password exposed => at least high
    pw = bl.ScanResult("a@b.com", [mk("Site", ["Email addresses", "Passwords"], "2015")], bl.PasswordResult())
    check(bl.assess(pw)["level"] in ("high", "critical"), "a password breach => high or worse")

    # financial exposed => critical
    fin = bl.ScanResult("a@b.com", [mk("Shop", ["Email addresses", "Credit cards"], "2016")], bl.PasswordResult())
    check(bl.assess(fin)["level"] == "critical", "financial data => critical")

    # a compromised password pushes to critical
    pwned = bl.ScanResult("a@b.com", [], bl.PasswordResult(True, True, 500))
    check(bl.assess(pwned)["level"] == "critical", "a known-pwned password => critical")

    # score is capped and recent breaches score higher than identical old ones
    recent = bl.assess(bl.ScanResult("a@b.com", [mk("R", ["Passwords"], "2025")], bl.PasswordResult()))["score"]
    old = bl.assess(bl.ScanResult("a@b.com", [mk("O", ["Passwords"], "2009")], bl.PasswordResult()))["score"]
    check(recent > old, f"a recent breach scores higher than an old one ({recent} > {old})")
    many = [mk(f"B{i}", ["Email addresses", "Passwords", "Credit cards"], "2024") for i in range(20)]
    check(bl.assess(bl.ScanResult("a@b.com", many, bl.PasswordResult()))["score"] == 100, "score caps at 100")

    # categories aggregate across breaches, worst-first
    multi = bl.ScanResult("a@b.com", [mk("A", ["Passwords", "Email addresses"], "2020"),
                                      mk("B", ["Email addresses", "Phone numbers"], "2021")], bl.PasswordResult())
    cats = bl.assess(multi)["categories"]
    check(cats[0]["severity"] == "critical" and cats[0]["name"] == "Passwords", "worst category (Passwords) is first")
    email_cat = next(c for c in cats if c["name"] == "Email addresses")
    check(email_cat["breaches"] == 2, "a category counts how many breaches exposed it")

    # remediation reacts to the findings
    acts = bl.assess(pw)["actions"]
    check(any("2FA" in a["title"] or "two-factor" in a["title"].lower() for a in acts), "recommends 2FA when breached")
    check(any("manager" in a["title"].lower() for a in acts), "recommends a password manager")
    check(all(a["severity"] in bl.SEVERITY_RANK for a in acts), "every action has a valid severity")


# ---------------------------------------------------------------- classification
def test_classify():
    check(bl.classify("Passwords") == "critical", "passwords => critical")
    check(bl.classify("Credit cards") == "critical", "credit cards => critical")
    check(bl.classify("Phone numbers") == "high", "phone => high")
    check(bl.classify("Physical addresses") == "high", "address => high")
    check(bl.classify("Usernames") == "medium", "username => medium")
    check(bl.classify("Email addresses") == "low", "email => low")
    check(bl.worst(["low", "critical", "medium"]) == "critical", "worst() picks the highest severity")


# ---------------------------------------------------------------- HTML safety
def test_html_escaping():
    evil = bl.Breach('<img src=x onerror=alert(1)>', '<script>alert(1)</script>', "evil.com",
                     "2020", 5, ['<b>Passwords</b>', 'Email"addresses'],
                     "<script>bad()</script>", True, False, "x")
    result = bl.ScanResult('me"@<x>.com', [evil], bl.PasswordResult(True, True, 10),
                           sources=["<b>src</b>"], scanned_at="2026-01-01")
    full = bl.render_report(result, standalone=True)
    check("<script>alert" not in full, "breach title with <script> is escaped")
    check("onerror=alert" not in full, "breach name with an event handler is escaped")
    check("&lt;script&gt;" in full, "dangerous markup is HTML-escaped")
    check('me"@<x>.com' not in full and "me&quot;@&lt;x&gt;.com" in full, "the email is escaped")
    frag = bl.render_report(result, standalone=False)
    check("<!doctype" not in frag.lower(), "the web-UI fragment has no document wrapper")
    check("<script>alert" not in frag, "the fragment is escaped too")

    # a completely clean report renders without error and says so
    clean = bl.ScanResult("ok@example.com", [], bl.PasswordResult(True, False, 0), scanned_at="2026-01-01")
    html = bl.render_report(clean)
    check("No known breaches" in html and "not found in any known breach" in html, "clean report states no exposure")


# ---------------------------------------------------------------- scan_email integration
def test_scan_email():
    payload = {"ExposedBreaches": {"breaches_details": [
        {"breach": "Dropbox", "xposed_date": "2012", "xposed_records": "68000000", "xposed_data": "Passwords"}]}}
    src = bl.XposedOrNot(lambda url, headers=None: (200, json.dumps(payload)))
    full = hashlib.sha1(b"pw").hexdigest().upper()
    res = bl.scan_email("a@b.com", src, password="pw",
                        pw_getter=lambda p: f"{full[5:]}:42")
    check(len(res.breaches) == 1 and res.password.pwned and res.password.count == 42,
          "scan_email combines breach lookup and password check")
    check(res.to_dict()["assessment"]["level"] in bl.SEVERITY_RANK or
          res.to_dict()["assessment"]["level"] in ("clear", "critical", "high", "medium", "low"),
          "to_dict() includes a full assessment")

    # a source failure is reported, not fatal
    def boom(url, headers=None):
        raise bl.SourceError("down")
    r2 = bl.scan_email("a@b.com", bl.XposedOrNot(boom), None)
    check(r2.errors and "down" in r2.errors[0], "a source error is captured, not raised")


for fn in [test_password_privacy, test_xposedornot, test_hibp, test_scoring,
           test_classify, test_html_escaping, test_scan_email]:
    print(f"\n# {fn.__name__}")
    fn()

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
