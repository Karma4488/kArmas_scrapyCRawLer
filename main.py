#!/usr/bin/env python3

import argparse
import json
import sqlite3
import sys
import time
import subprocess
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from scrapy.utils.log import configure_logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configurations
DB_FILE = "karmas_shadows.db"
SQLMAP_PATH = str(Path.home() / "sqlmap" / "sqlmap.py")

# Tamper tiers for SQLmap
TAMPER_TIERS = {
    1: ["space2comment", "between", "randomcase"],
    2: ["space2plus", "charencode", "apostrophemask", "base64encode"],
    3: ["greatest", "ifnull2ifisnull", "space2mysqlblank", "versionedkeywords", "equaltolike"],
}

SQLMAP_BASE_ARGS = [
    "--batch",
    "--level=3",
    "--risk=2",
    "--random-agent",
    "--threads=1",
    "--flush-session",
    "--output-dir", "sqlmap_results",
]

# Initialize the database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            type TEXT, 
            target TEXT, 
            severity TEXT, 
            details TEXT, 
            ts INTEGER
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic (
            ts INTEGER, 
            method TEXT, 
            url TEXT, 
            status INTEGER,
            req_headers TEXT, 
            resp_headers TEXT, 
            resp_size INTEGER
        )
        """
    )
    conn.commit()
    conn.close()

init_db()

# SQL errors and XSS payloads
SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "sqlstate", "ora-", "microsoft ole db",
    "pg_query", "unclosed quotation mark", "error in your sql", "near",
    "quoted string not properly terminated",
]

XSS_PAYLOADS = [
    '"<script>alert(1)</script>',
    '"<img src=x onerror=alert(1)>',
    '"<svg onload=alert(1)>',
]

CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "_csrf", "csrfmiddlewaretoken", "authenticity_token",
    "__requestverificationtoken", "token", "anti-csrf-token", "xsrf", "xsrf-token",
]

class KArmasCrawler(CrawlSpider):
    name = "kArmasCrawler"
    
    custom_settings = {
        "ROBOTSTXT_OBEY": False,
        "USER_AGENT": "kArmas-ZAP-FULL/1.3 (Phantom)",
        "LOG_LEVEL": "INFO",
        "DEPTH_LIMIT": 7,
        "CONCURRENT_REQUESTS": 5,
        "DOWNLOAD_TIMEOUT": 15,
        "RETRY_ENABLED": True,
        "RETRY_TIMES": 2,
        "HTTPCACHE_ENABLED": True,
    }

    rules = (Rule(LinkExtractor(allow=()), callback="parse_item", follow=True),)

    def __init__(self, *args, allowed_domain=None, headers=None, tamper_tier=1, sqlmap_auto=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_domain = allowed_domain
        self.headers = headers or {}
        self.visited = set()
        self.tamper_tier = tamper_tier
        self.sqlmap_auto = sqlmap_auto

    def start_requests(self):
        for url in self.start_urls:
            yield scrapy.Request(url, headers=self.headers, callback=self.parse, meta={"depth": 0})

    def parse(self, response):
        url = response.url
        if url in self.visited:
            return
        self.visited.add(url)

        self.log_traffic(response)
    
        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {}
        if params:
            self.store_finding("Params", url, "INFO", ",".join(params.keys()))
        
        yield from self.parse_item(response)

    def parse_item(self, response):
        self.log(f"[CRAWLER] {response.url} ({response.status})")
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

# Launch sequence
def main():
    parser = argparse.ArgumentParser(description="kArmas_scrapyCrawler")
    parser.add_argument("target", help="Starting URL")
    parser.add_argument("--sqlmap-auto", action="store_true", help="Auto-run sqlmap on HIGH findings")
    args = parser.parse_args()

    configure_logging()
    process = CrawlerProcess()
    process.crawl(
        KArmasCrawler,
        start_urls=[args.target],
        sqlmap_auto=args.sqlmap_auto,
    )
    process.start()

if __name__ == "__main__":
    main()