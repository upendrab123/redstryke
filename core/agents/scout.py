from __future__ import annotations
import asyncio
import ipaddress
import logging
import re
import socket
import subprocess
from typing import Any
from urllib.parse import urlparse

import httpx

from core.agents.base import BaseAgent, make_event

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "admin", "cdn", "api", "dev", "test",
    "stage", "staging", "beta", "demo", "shop", "store", "m", "mobile",
    "app", "my", "portal", "login", "auth", "sso", "idp",
    "gitlab", "jenkins", "jira", "confluence", "wiki", "docs",
    "support", "help", "status", "uptime", "monitor", "metrics",
    "dashboard", "analytics", "tracking", "pixel", "static",
    "assets", "images", "img", "css", "js", "media", "upload",
    "download", "files", "ftp", "backup", "db", "database",
    "redis", "mq", "queue", "worker", "jobs", "cron",
    "web", "www2", "www3", "old", "new", "origin", "edge",
    "lb", "loadbalancer", "gateway", "api-gateway", "proxy",
    "waf", "firewall", "ids", "ips", "security", "audit",
    "report", "reports", "logs", "log", "syslog", "grafana",
    "prometheus", "elk", "kibana", "elastic", "search", "solr",
    "cdn", "static", "img", "video", "stream", "live",
    "calendar", "mail2", "owa", "exchange", "autodiscover",
    "lyncdiscover", "sip", "meet", "teams", "zoom", "webex",
    "remote2", "rdp", "rdweb", "citrix", "vdi", "horizon",
    "www3", "www4", "m2", "en", "fr", "de", "jp", "cn", "es",
    "it", "pt", "ru", "ar", "in", "id", "my", "th", "vn",
    "ph", "sg", "hk", "tw", "kr", "au", "nz",
]


SUBDOMAINS_EXTENDED = [
    "ac", "access", "account", "accounts", "activate", "active",
    "activity", "ad", "affiliate", "affiliates", "ajax", "alert",
    "alerts", "all", "announce", "announcements", "any", "ap",
    "api2", "api3", "apis", "app2", "app3", "apps", "archive",
    "asia", "at", "atom", "attach", "attachment", "auctions",
    "audio", "auth2", "author", "auto", "autoconfig", "autodiscover",
    "avatar", "aws", "azure", "badge", "banner", "banners",
    "base", "bbs", "be", "big", "billing", "board", "book",
    "booking", "bot", "bugs", "build", "business", "button",
    "buy", "buzz", "ca", "cache", "call", "campaign", "campaigns",
    "cancel", "captcha", "card", "career", "careers", "cart",
    "catalog", "catch", "cdn2", "cgi", "channel", "chat",
    "check", "checkout", "chk", "chrome", "city", "classic",
    "click", "client", "clients", "cloud", "club", "cluster",
    "cnt", "code", "com", "commercial", "community", "company",
    "compare", "comprar", "conexion", "confirm", "connect",
    "console", "contact", "contact-us", "contactus", "content",
    "contest", "contracts", "control", "core", "corp", "corporate",
    "counter", "country", "coupon", "coupons", "courses",
    "cp", "cpanel", "crack", "create", "creative", "credit",
    "creditcard", "crm", "cross", "css", "custhelp", "custom",
    "customer", "customers", "customize", "cv", "d", "daemon",
    "data", "date", "deal", "dealer", "deals", "deploy", "design",
    "desktop", "dest", "developer", "developers", "device",
    "discount", "discover", "discussion", "display", "dm",
    "dns", "dns1", "dns2", "dns3", "dns4", "dns05", "dns09",
    "dns1", "dns2", "dns3", "dns4", "dns5", "dns6", "dns7",
    "dns8", "dns9", "do", "doc", "domain", "domains", "donate",
    "dp", "dragon", "drive", "dynamic", "e", "e-card", "e-shop",
    "earnings", "east", "ec", "echo", "edit", "editor", "education",
    "elegir", "email", "emergency", "employer", "empty", "enable",
    "encuestas", "eng", "engine", "engineering", "enter", "enterprise",
    "error", "errors", "es", "estore", "et", "eu", "event",
    "events", "ex", "exch", "exchange", "exclude", "exe",
    "ext", "extranet", "extra", "extranet", "ez", "f", "facebook",
    "faq", "faqs", "favorites", "fax", "feature", "features",
    "feed", "feedback", "feeds", "file", "fileadmin", "filemanager",
    "filetransfer", "files2", "filter", "finance", "firewall",
    "first", "fixtures", "flash", "focus", "folder", "for",
    "forgot", "form", "forms", "forum", "forums", "forward",
    "foundation", "free", "friend", "from", "front", "ftp2",
    "fund", "gadget", "gadgets", "gallery", "game", "games",
    "garbage", "garden", "gate", "gather", "gcc", "general",
    "generic", "gestio", "gestor", "gift", "gifts", "git",
    "github", "give", "global", "glue", "gmail", "go", "gopher",
    "goto", "gov", "gpo", "graph", "graphics", "graphql",
    "group", "groups", "grp", "guest", "guide", "guru", "h",
    "hack", "hacker", "half", "help", "helpdesk", "here",
    "hero", "hide", "high", "hip", "hire", "home", "homepage",
    "homes", "homolog", "homologation", "horizon", "host",
    "hosting", "hostmaster", "hot", "hotel", "hoteles", "hotspot",
    "hr", "html", "http", "https", "hub", "i", "ib", "ic",
    "icon", "icons", "id", "idea", "ideas", "im", "image",
    "imail", "imap", "img2", "img3", "imgs", "import", "in",
    "inbound", "index", "info", "informacion", "informatica",
    "init", "inicio", "inmate", "inquiry", "inside", "instant",
    "instore", "int", "intel", "inter", "internal", "internet",
    "intra", "intranet", "investor", "investors", "invitation",
    "invite", "invoice", "invoices", "io", "ip", "ipad", "iphone",
    "ipv4", "ipv6", "irc", "is", "isapi", "isatap", "iso",
    "issue", "issues", "it", "item", "items", "its", "j",
    "java", "job", "jobs", "join", "journal", "json", "k",
    "kb", "keep", "kernel", "key", "keyword", "keywords", "kids",
    "kill", "kit", "l", "label", "lab", "label", "lamer",
    "landing", "lang", "last", "lat", "layer", "layout", "lazy",
    "ldap", "ldapl", "learn", "learning", "leave", "lecture",
    "left", "legal", "libraries", "library", "light", "link",
    "links", "linux", "list", "lists", "live", "load", "loader",
    "local", "localhost", "locate", "location", "login", "logo",
    "logout", "logs", "look", "loyalty", "lso", "lt", "luck",
    "lucky", "luggage", "lv", "lyrics", "m2", "machine", "macro",
    "magic", "mail1", "mail2", "mail3", "mail4", "mail5",
    "mail6", "mail7", "mail8", "mail9", "mailer", "mailing",
    "mailman", "mails", "main", "maintain", "maintenance",
    "manage", "management", "manager", "manual", "map", "maps",
    "mark", "marketing", "marketplace", "mas", "master",
    "maven", "max", "mb", "mc", "md", "me", "media", "media2",
    "meet", "meeting", "meetings", "member", "members", "memo",
    "menu", "merchant", "merchants", "message", "messages",
    "messenger", "meter", "mexico", "mg", "miami", "micro",
    "middle", "middleware", "mig", "migration", "mind", "mini",
    "mining", "mirror", "mirrors", "mis", "misc", "mm", "mmf",
    "mo", "mob", "mobi", "mobile", "mobility", "mod", "model",
    "modem", "mods", "module", "modules", "mon", "monitor",
    "monitoring", "more", "most", "motd", "mouse", "move",
    "movie", "movies", "mp3", "mq", "mr", "ms", "msg", "msn",
    "mt", "multi", "music", "mx", "my", "myspace", "mysql",
    "n", "name", "named", "nano", "native", "nav", "navigation",
    "ne", "net", "net2", "netbg", "netmail", "nets", "network",
    "networks", "new", "news", "newsletter", "newyork", "next",
    "nexus", "nf", "nice", "nl", "node", "nobody", "nodename",
    "noreply", "north", "notes", "notice", "notification",
    "notifications", "notify", "now", "np", "ns", "ns0", "ns1",
    "ns2", "ns3", "ns4", "ns5", "ns6", "ns7", "ns8", "ns9",
    "nsc", "nsl", "nsmail", "ntp", "null", "numbers", "o",
    "object", "oc", "ocs", "office", "official", "officials",
    "ok", "old", "old2", "oldmail", "online", "oo", "open",
    "openid", "opensource", "operator", "ops", "opt", "optimize",
    "option", "options", "or", "order", "orders", "org", "origin",
    "os", "osc", "other", "others", "out", "outage", "outages",
    "outlook", "outside", "owa", "own", "owner", "p", "p3p",
    "pac", "page", "pages", "paid", "painel", "panel", "paper",
    "paris", "part", "partner", "partners", "party", "pass",
    "passport", "password", "paste", "patch", "pay", "payment",
    "payments", "pc", "pdf", "pds", "pe", "peer", "people",
    "perf", "performance", "person", "personal", "pg", "ph",
    "phone", "photo", "photos", "php", "phpMyAdmin", "pic",
    "pics", "picture", "pictures", "pl", "place", "plan",
    "plane", "planet", "plans", "play", "player", "playground",
    "plugin", "plugins", "plus", "pm", "pn", "pod", "poc",
    "podcast", "poker", "pol", "policy", "poll", "polls",
    "pool", "pop", "pop3", "popular", "portal", "post", "postfix",
    "postmaster", "power", "powered", "pp", "pr", "prd",
    "pre", "pred", "pref", "prefs", "premio", "premium",
    "preprod", "press", "preview", "print", "printer", "privacy",
    "private", "privilege", "pro", "prob", "probe", "process",
    "prod", "producer", "product", "production", "productions",
    "products", "profile", "profiles", "professor", "program",
    "project", "projects", "promo", "promos", "promote",
    "promotion", "proof", "proposal", "protect", "protected",
    "protection", "proto", "prototype", "proxy", "prueba",
    "ps", "psd", "pub", "public", "publish", "publisher",
    "publishing", "pull", "pump", "purchase", "purge", "push",
    "pw", "pwd", "py", "qa", "qmail", "qs", "qual", "quality",
    "query", "queue", "quick", "quiet", "r", "radio", "radius",
    "random", "rank", "rating", "ratings", "rd", "rdp", "re",
    "reach", "read", "reader", "readme", "realtime", "receive",
    "recovery", "recruitment", "recurit", "recuritment", "recycle",
    "red", "redir", "redirect", "reduced", "ref", "refer",
    "reference", "referer", "referral", "referrals", "register",
    "registration", "reg", "regions", "relay", "release",
    "releases", "remote", "remove", "renew", "rep", "repair",
    "repeat", "replace", "replica", "replication", "reply",
    "report", "reports", "repre", "reps", "request", "requests",
    "research", "reseller", "reservation", "reservations",
    "reset", "resolve", "resource", "resources", "response",
    "rest", "restore", "restricted", "result", "results",
    "resume", "retail", "retailer", "retailers", "retired",
    "retirement", "retour", "retrieve", "return", "returns",
    "review", "reviews", "revise", "revision", "rss", "rsvp",
    "rule", "rules", "run", "runtime", "s", "sac", "sale",
    "sales", "sample", "samples", "sandbox", "save", "sb",
    "sc", "scan", "scanner", "schedule", "scheduled", "schema",
    "school", "science", "scope", "score", "screen", "screens",
    "script", "scripts", "scrum", "sc", "sd", "sds", "search",
    "secure2", "secure", "secured", "security", "segment",
    "select", "self", "seller", "send", "sender", "sense",
    "server", "service", "services", "session", "sessions",
    "setup", "sf", "sg", "sh", "share", "shared", "sheet",
    "shell", "shield", "ship", "shipping", "shop", "shopping",
    "show", "showtime", "sign", "signal", "signin", "signout",
    "signup", "sim", "simple", "simply", "simul", "site",
    "sitemap", "sites", "sk", "ski", "skip", "sky", "sla",
    "slave", "sleep", "slide", "slides", "sln", "slx", "small",
    "smart", "sms", "smtp2", "sn", "snmp", "sns", "so", "social",
    "socket", "socks", "soft", "software", "sol", "solution",
    "solutions", "son", "song", "soon", "sort", "source",
    "sourcecode", "south", "space", "spam", "span", "spare",
    "spec", "special", "splash", "sponsor", "sport", "sports",
    "spot", "spy", "sql", "squid", "sr", "src", "srch", "sso",
    "st", "staff", "stage", "staging", "stamp", "standalone",
    "standard", "start", "static", "stat", "state", "static2",
    "static3", "stats", "status", "std", "steam", "step",
    "stock", "stop", "store", "stores", "stored", "stp",
    "stream", "studio", "study", "style", "styles", "sub",
    "submit", "subscribe", "subscriber", "subscription",
    "subway", "success", "summary", "sun", "sup", "super",
    "supplier", "suppliers", "support", "supra", "sure",
    "surf", "survey", "surveys", "svc", "svn", "sw", "swap",
    "swiss", "switch", "syllabus", "sync", "syndication",
    "sys", "syslog", "system", "systems", "t", "tabela",
    "table", "tablet", "tag", "tags", "talk", "tape", "target",
    "task", "tasks", "tcp", "team", "teams", "tech", "technology",
    "tel", "tele", "telecom", "telephone", "telesales",
    "temporary", "term", "terminal", "terms", "test", "testing",
    "test2", "tests", "text", "theme", "themes", "think",
    "this", "thread", "threads", "ticket", "tickets", "time",
    "timer", "times", "tiny", "tip", "tips", "titan", "tk",
    "tmp", "to", "tod", "today", "token", "tokken", "toll",
    "tomcat", "tool", "tools", "top", "topic", "topics",
    "tor", "tos", "tour", "tours", "town", "tp", "tr",
    "track", "trackback", "tracker", "tracking", "trading",
    "traduccion", "traffic", "training", "transfer", "translate",
    "translation", "travel", "trends", "trial", "tribune",
    "trip", "trivial", "true", "trunk", "trust", "try", "tt",
    "tube", "tunnel", "tv", "tw", "tweet", "twitter", "tx",
    "txt", "typo", "u", "ucp", "ug", "uk", "ultra", "un",
    "una", "unavailable", "undef", "undefined", "undo", "uni",
    "unified", "unique", "unit", "unite", "unity", "universal",
    "unix", "unknown", "unlimited", "unlock", "unprotect",
    "unsecured", "unsuscribe", "untitled", "unused", "update",
    "updates", "upgrade", "upload", "uploads", "ups", "uptime",
    "urban", "url", "urL", "urn", "us", "us-east", "usage",
    "usenet", "user", "users", "us-west", "ut", "util", "utils",
    "v", "vacation", "validate", "validation", "value", "values",
    "vcal", "vcard", "vcenter", "vdi", "vdir", "ve", "vendor",
    "vendors", "ver", "verify", "vers", "version", "versions",
    "vertical", "vg", "via", "video", "videos", "view", "views",
    "vip", "virtual", "virus", "visa", "visit", "visitor",
    "visitors", "vista", "visual", "vital", "vlan", "vm",
    "vnet", "vod", "voice", "vol", "volume", "vote", "vpn",
    "w", "waf", "wait", "wall", "want", "war", "warehouse",
    "warn", "warning", "warnings", "watch", "watcher", "water",
    "wave", "wcc", "wci", "wclock", "welcome", "well", "west",
    "wg", "what", "whatsnew", "wheel", "whistle", "white",
    "whitepages", "who", "whois", "whole", "wholesale", "why",
    "wi", "wide", "widget", "widgets", "wifi", "win", "wince",
    "window", "windows", "wine", "winmail", "wins", "wire",
    "wireless", "wis", "wisdom", "wise", "wish", "wishlist",
    "with", "wiz", "wizard", "wm", "wml", "wmp", "wmx",
    "wo", "woman", "women", "wonder", "wood", "word", "wordpress",
    "work", "workflow", "works", "workshop", "world", "wow",
    "wp", "wp2", "wpad", "wpl", "wpmu", "wrap", "writer",
    "ws", "wt", "ww", "ww2", "ww3", "ww4", "wwdr", "wws",
    "wwv", "www2", "www3", "www4", "www5", "www6", "www7",
    "www8", "www9", "www10", "www11", "www12", "www13",
    "www14", "www15", "www16", "www17", "www18", "www19",
    "www20", "www21", "www22", "www23", "www24", "www25",
    "x", "xchange", "xl", "xml", "xmlrpc", "xoxo", "xs",
    "xspf", "xss", "xx", "xxx", "y", "yahoo", "yard", "yell",
    "yellow", "yes", "yesterday", "you", "young", "your",
    "yours", "yourself", "yt", "z", "zero", "zine", "zip",
    "zone", "zoom",
]


SUBDOMAIN_WORDLIST = list(dict.fromkeys(COMMON_SUBDOMAINS + SUBDOMAINS_EXTENDED))

CDN_WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "akamai": ["akamaighost", "akamai"],
    "fastly": ["fastly", "x-fastly"],
    "cloudfront": ["cloudfront", "x-amz-cf"],
    "incapsula": ["incapsula", "x-iinfo"],
    "sucuri": ["sucuri", "x-sucuri"],
    "stackpath": ["stackpath"],
    "imperva": ["imperva", "x-cdn"],
    "keycdn": ["keycdn"],
    "azure": ["azure", "x-azure"],
}


class ScoutAgent(BaseAgent):
    name = "SCOUT"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def run(self, context: dict) -> dict:
        target_url = context.get("target_url", "")
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(":")[0]

        self.emit_running(f"Starting DNS enumeration for {domain}")
        result: dict[str, Any] = {
            "domain": domain,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "zone_transfer": None,
            "subdomains": [],
            "cdn_waf": None,
            "ip_info": {},
            "findings": [],
        }

        a_records = self._resolve_a(domain)
        result["a_records"] = a_records
        self.emit_running(f"A records: {a_records}")

        if a_records:
            cdn = self._detect_cdn_waf(a_records, domain)
            result["cdn_waf"] = cdn
            if cdn:
                self.emit_running(f"CDN/WAF detected: {cdn}")
                result.setdefault("findings", []).append({
                    "type": "cdn_waf_detected",
                    "detail": f"CDN/WAF detected: {cdn}",
                    "ips": a_records,
                })

        self.emit_running(f"Resolving MX records...")
        mx = await self._resolve_mx(domain)
        result["mx_records"] = mx
        if mx:
            self.emit_running(f"MX records: {[m[1] for m in mx]}")

        self.emit_running(f"Resolving NS records...")
        ns = await self._resolve_ns(domain)
        result["ns_records"] = ns
        if ns:
            self.emit_running(f"NS records: {ns}")

            self.emit_running(f"Testing zone transfer on {domain}...")
            zt = await self._test_zone_transfer(domain, ns)
            result["zone_transfer"] = zt
            if zt:
                self.emit_complete(f"Zone transfer VULNERABLE on {ns[0]}")
                result.setdefault("findings", []).append({
                    "type": "zone_transfer",
                    "detail": f"Zone transfer successful via {ns[0]}",
                    "records": zt[:5],
                })
            else:
                self.emit_running("Zone transfer not available")

        self.emit_running(f"Resolving TXT records...")
        txt = await self._resolve_txt(domain)
        result["txt_records"] = txt
        if txt:
            for t in txt:
                if "spf" in t.lower():
                    self.emit_running(f"SPF record found")
                elif "dkim" in t.lower() or "v=dkim" in t.lower():
                    self.emit_running(f"DKIM record found")
                elif "dmarc" in t.lower():
                    self.emit_running(f"DMARC record found")

        self.emit_running(f"Resolving CNAME...")
        cname = await self._resolve_cname(domain)
        result["cname_records"] = cname

        self.emit_running(f"Brute-forcing subdomains (~{len(SUBDOMAIN_WORDLIST)} words)...")
        subdomains = await self._brute_force_subdomains(domain)
        result["subdomains"] = subdomains
        if subdomains:
            found = [s["subdomain"] for s in subdomains[:20]]
            self.emit_running(f"Subdomains found: {found}")

        if a_records:
            result["ip_info"] = await self._get_ip_info(a_records[0])

        self.emit_complete(f"Scout complete: {len(a_records)} A, {len(mx)} MX, {len(ns)} NS, {len(subdomains)} subdomains")
        return result

    def _resolve_a(self, domain: str) -> list[str]:
        try:
            results = []
            for info in socket.getaddrinfo(domain, 80):
                ip = info[4][0]
                if ip not in results and ":" not in ip:
                    results.append(ip)
            return results[:10]
        except socket.gaierror:
            return []

    async def _resolve_mx(self, domain: str) -> list[tuple[int, str]]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-Command",
                f"Resolve-DnsName -Name '{domain}' -Type MX -ErrorAction SilentlyContinue | Select-Object NameExchange, Preference | ConvertTo-Json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            import json
            data = json.loads(stdout.decode().strip() or "[]")
            if isinstance(data, dict):
                data = [data]
            return [(d.get("Preference", 10), d.get("NameExchange", "")) for d in data if d.get("NameExchange")]
        except Exception:
            return []

    async def _resolve_ns(self, domain: str) -> list[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-Command",
                f"Resolve-DnsName -Name '{domain}' -Type NS -ErrorAction SilentlyContinue | Select-Object NameHost | ConvertTo-Json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            import json
            data = json.loads(stdout.decode().strip() or "[]")
            if isinstance(data, dict):
                data = [data]
            return [d.get("NameHost", "") for d in data if d.get("NameHost")]
        except Exception:
            return []

    async def _resolve_txt(self, domain: str) -> list[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-Command",
                f"Resolve-DnsName -Name '{domain}' -Type TXT -ErrorAction SilentlyContinue | Select-Object Strings | ConvertTo-Json -Depth 2",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            import json
            data = json.loads(stdout.decode().strip() or "[]")
            if isinstance(data, dict):
                data = [data]
            texts = []
            for d in data:
                s = d.get("Strings")
                if isinstance(s, list):
                    texts.extend(s)
                elif isinstance(s, str):
                    texts.append(s)
            return texts
        except Exception:
            return []

    async def _resolve_cname(self, domain: str) -> list[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-Command",
                f"Resolve-DnsName -Name '{domain}' -Type CNAME -ErrorAction SilentlyContinue | Select-Object NameHost | ConvertTo-Json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            import json
            data = json.loads(stdout.decode().strip() or "[]")
            if isinstance(data, dict):
                data = [data]
            return [d.get("NameHost", "") for d in data if d.get("NameHost")]
        except Exception:
            return []

    async def _test_zone_transfer(self, domain: str, nameservers: list[str]) -> list[str] | None:
        if not nameservers:
            return None
        try:
            ns = nameservers[0].rstrip(".")
            proc = await asyncio.create_subprocess_exec(
                "nslookup", "-type=ns", domain, ns,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode().lower()
            if "zone" in output and ("primary name server" in output or "origin" in output):
                lines = [l.strip() for l in output.split("\n") if l.strip() and "can't" not in l.lower()]
                return lines[:20]
            return None
        except Exception:
            return None

    async def _brute_force_subdomains(self, domain: str) -> list[dict]:
        found = []
        sem = asyncio.Semaphore(20)
        loop = asyncio.get_event_loop()

        async def check(sub: str) -> dict | None:
            async with sem:
                fqdn = f"{sub}.{domain}"
                try:
                    def sync_resolve():
                        try:
                            return list(set(
                                info[4][0] for info in socket.getaddrinfo(fqdn, 80)
                                if ":" not in info[4][0]
                            ))
                        except socket.gaierror:
                            return []
                    ips = await loop.run_in_executor(None, sync_resolve)
                    if ips:
                        return {"subdomain": fqdn, "ips": ips}
                except Exception:
                    pass
                return None

        tasks = [check(sub) for sub in SUBDOMAIN_WORDLIST]
        batch_size = 100
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch)
            for r in results:
                if r:
                    found.append(r)
                    self.emit_running(f"Found subdomain: {r['subdomain']} -> {r['ips']}")
        return found

    def _detect_cdn_waf(self, ips: list[str], domain: str) -> str | None:
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private:
                    continue
            except ValueError:
                pass
        hostname = domain.lower()
        for cdn_name, sigs in CDN_WAF_SIGNATURES.items():
            for sig in sigs:
                if sig in hostname:
                    return cdn_name
        return None

    async def _get_ip_info(self, ip: str) -> dict:
        info = {"ip": ip}
        try:
            addr = ipaddress.ip_address(ip)
            info["is_private"] = addr.is_private
            info["is_global"] = addr.is_global
            if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168."):
                info["type"] = "private"
            elif ip.startswith("127."):
                info["type"] = "loopback"
            else:
                info["type"] = "public"
        except ValueError:
            info["type"] = "unknown"
        return info
