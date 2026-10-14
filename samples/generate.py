"""Generate realistic sample logs containing normal traffic and known attacks.

Only documentation IP ranges (RFC 5737) and private ranges are used.

    python samples/generate.py          # writes samples/auth.log and samples/access.log
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).parent
rng = random.Random(42)
START = datetime(2026, 10, 12, 8, 0, 0)

LEGIT_USERS = ["alice", "bob", "deploy"]
LEGIT_IPS = ["10.0.0.12", "10.0.0.15", "192.168.1.20"]
SPRAY_USERS = ["admin", "test", "oracle", "postgres", "ubuntu", "guest", "user", "ftp", "pi"]


def syslog(ts: datetime, msg: str, pid: int) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} srv-web01 sshd[{pid}]: {msg}"


def gen_auth() -> list[str]:
    lines: list[tuple[datetime, str]] = []
    # Normal logins throughout the day
    for _ in range(40):
        ts = START + timedelta(seconds=rng.randint(0, 10 * 3600))
        user, ip = rng.choice(LEGIT_USERS), rng.choice(LEGIT_IPS)
        method = rng.choice(["password", "publickey"])
        lines.append((ts, syslog(ts, f"Accepted {method} for {user} from {ip} port "
                                     f"{rng.randint(40000, 65000)} ssh2", rng.randint(1000, 9999))))
    # A few honest typos
    for _ in range(4):
        ts = START + timedelta(seconds=rng.randint(0, 10 * 3600))
        lines.append((ts, syslog(ts, f"Failed password for alice from 10.0.0.12 port "
                                     f"{rng.randint(40000, 65000)} ssh2", rng.randint(1000, 9999))))

    # 1) Brute force on root that eventually succeeds -> critical
    ts = START + timedelta(hours=2, minutes=13)
    for _ in range(38):
        ts += timedelta(seconds=rng.randint(2, 6))
        lines.append((ts, syslog(ts, f"Failed password for root from 203.0.113.45 port "
                                     f"{rng.randint(40000, 65000)} ssh2", 4242)))
    ts += timedelta(seconds=4)
    lines.append((ts, syslog(ts, "Accepted password for root from 203.0.113.45 port 51122 ssh2", 4243)))

    # 2) Password spraying across many usernames, slow (avoids brute force window)
    ts = START + timedelta(hours=5)
    for user in SPRAY_USERS:
        ts += timedelta(seconds=rng.randint(70, 110))
        pid = rng.randint(1000, 9999)
        lines.append((ts, syslog(ts, f"Invalid user {user} from 198.51.100.23 port "
                                     f"{rng.randint(40000, 65000)}", pid)))
        lines.append((ts, syslog(ts, f"Failed password for invalid user {user} from 198.51.100.23 "
                                     f"port {rng.randint(40000, 65000)} ssh2", pid)))

    # Noise sshd lines that the parser must ignore
    for _ in range(10):
        ts = START + timedelta(seconds=rng.randint(0, 10 * 3600))
        lines.append((ts, syslog(ts, "pam_unix(sshd:session): session opened for user alice(uid=1000)",
                                 rng.randint(1000, 9999))))
    lines.sort(key=lambda x: x[0])
    return [line for _, line in lines]


def web(ts: datetime, ip: str, method: str, path: str, status: int, ua: str) -> str:
    return (f'{ip} - - [{ts:%d}/{ts:%b}/{ts:%Y}:{ts:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
            f'{status} {rng.randint(200, 9000)} "-" "{ua}"')


BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"
PAGES = ["/", "/about", "/products", "/products?id=3", "/contact", "/static/app.css",
         "/static/app.js", "/login", "/blog/securing-ssh"]
WORDLIST = ["admin", "backup", "old", "test", "dev", "api", "uploads", "private", "cgi-bin",
            "includes", "tmp", "db", "panel", "console", "staging", "portal", "manager",
            "dashboard", "files", "logs", "secret", "hidden", "install", "setup", "debug"]


def gen_access() -> list[str]:
    lines: list[tuple[datetime, str]] = []
    for _ in range(300):
        ts = START + timedelta(seconds=rng.randint(0, 10 * 3600))
        ip = f"192.0.2.{rng.randint(10, 60)}"
        path = rng.choice(PAGES)
        status = 200 if rng.random() > 0.03 else 404
        lines.append((ts, web(ts, ip, "GET", path, status, BROWSER)))

    # 3) Directory scanning with a known tool
    ts = START + timedelta(hours=3)
    for word in WORDLIST:
        ts += timedelta(seconds=rng.randint(1, 3))
        lines.append((ts, web(ts, "192.0.2.77", "GET", f"/{word}/", 404,
                              "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)")))
    for path in ["/.env", "/.git/config", "/wp-config.php", "/phpmyadmin/", "/backup.sql"]:
        ts += timedelta(seconds=2)
        lines.append((ts, web(ts, "192.0.2.77", "GET", path, 404,
                              "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000002)")))

    # 4) SQL injection with sqlmap; one payload returns 200
    ts = START + timedelta(hours=6, minutes=40)
    payloads = [
        ("/products?id=3%27%20OR%20%271%27%3D%271", 500),
        ("/products?id=3%20UNION%20SELECT%20username,password%20FROM%20users--", 200),
        ("/products?id=3%20AND%20SLEEP(5)", 200),
        ("/products?id=3;DROP%20TABLE%20users", 500),
    ]
    for path, status in payloads:
        ts += timedelta(seconds=rng.randint(3, 8))
        lines.append((ts, web(ts, "203.0.113.99", "GET", path, status, "sqlmap/1.8.4#stable")))

    # 5) Path traversal and XSS attempts from a manual attacker
    ts = START + timedelta(hours=8)
    for path, status in [("/download?file=../../../../etc/passwd", 403),
                         ("/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", 403),
                         ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)]:
        ts += timedelta(seconds=rng.randint(5, 20))
        lines.append((ts, web(ts, "198.51.100.150", "GET", path, status, BROWSER)))

    # Malformed lines (TLS handshake on port 80) that must be skipped
    lines.append((START, '192.0.2.200 - - [12/Oct/2026:08:00:00 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"'))
    lines.sort(key=lambda x: x[0])
    return [line for _, line in lines]


if __name__ == "__main__":
    (OUT / "auth.log").write_text("\n".join(gen_auth()) + "\n", encoding="utf-8")
    (OUT / "access.log").write_text("\n".join(gen_access()) + "\n", encoding="utf-8")
    print("Wrote samples/auth.log and samples/access.log")
