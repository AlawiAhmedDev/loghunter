from datetime import datetime, timedelta
from pathlib import Path

from loghunter.detectors import (
    Config,
    detect_password_spraying,
    detect_scanner_user_agents,
    detect_ssh_bruteforce,
    detect_success_after_bruteforce,
    detect_web_attacks,
    detect_web_scanning,
    run_all,
)
from loghunter.models import Event
from loghunter.parsers import parse_files

T0 = datetime(2026, 10, 12, 10, 0, 0)
SAMPLES = Path(__file__).parent.parent / "samples"


def ssh(action, ip="203.0.113.45", user="root", seconds=0):
    return Event(T0 + timedelta(seconds=seconds), "ssh", action, ip, user=user, raw=action)


def web(path, status=404, ip="192.0.2.77", ua="Mozilla/5.0", seconds=0):
    return Event(T0 + timedelta(seconds=seconds), "web", "http_request", ip,
                 method="GET", path=path, status=status, user_agent=ua, raw=path)


# --- SSH brute force --------------------------------------------------------

def test_bruteforce_below_threshold_no_alert():
    events = [ssh("ssh_failed", seconds=i) for i in range(4)]
    assert detect_ssh_bruteforce(events, Config()) == []


def test_bruteforce_at_threshold_alerts():
    events = [ssh("ssh_failed", seconds=i * 10) for i in range(5)]
    alerts = detect_ssh_bruteforce(events, Config())
    assert len(alerts) == 1
    assert alerts[0].severity == "high"
    assert alerts[0].mitre.startswith("T1110.001")


def test_bruteforce_spread_outside_window_no_alert():
    # 5 failures, one every 10 minutes: never 5 inside a 5-minute window
    events = [ssh("ssh_failed", seconds=i * 600) for i in range(5)]
    assert detect_ssh_bruteforce(events, Config()) == []


def test_bruteforce_massive_is_critical():
    events = [ssh("ssh_failed", seconds=i) for i in range(60)]
    assert detect_ssh_bruteforce(events, Config())[0].severity == "critical"


def test_invalid_user_and_failed_counted_once():
    events = []
    for i in range(3):
        events.append(ssh("ssh_invalid_user", user=f"u{i}", seconds=i * 10))
        events.append(ssh("ssh_failed", user=f"u{i}", seconds=i * 10))
    # 3 attempts, not 6 -> below threshold
    assert detect_ssh_bruteforce(events, Config()) == []


def test_success_after_bruteforce_is_critical():
    events = [ssh("ssh_failed", seconds=i) for i in range(6)]
    events.append(ssh("ssh_accepted", seconds=10))
    alerts = detect_success_after_bruteforce(events, Config())
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"
    assert "root" in alerts[0].description


def test_normal_login_after_one_typo_is_fine():
    events = [ssh("ssh_failed", ip="10.0.0.12", user="alice"),
              ssh("ssh_accepted", ip="10.0.0.12", user="alice", seconds=5)]
    assert detect_success_after_bruteforce(events, Config()) == []


def test_password_spraying():
    events = [ssh("ssh_failed", ip="198.51.100.23", user=u, seconds=i * 90)
              for i, u in enumerate(["admin", "test", "oracle", "pi", "guest"])]
    alerts = detect_password_spraying(events, Config())
    assert len(alerts) == 1
    assert alerts[0].count == 5


# --- Web --------------------------------------------------------------------

def test_sql_injection_url_encoded():
    alerts = detect_web_attacks([web("/p?id=1%20UNION%20SELECT%20pass%20FROM%20users")], Config())
    assert alerts[0].rule == "web_sql_injection"


def test_sql_injection_with_2xx_escalates_to_critical():
    alerts = detect_web_attacks([web("/p?id=1%20UNION%20SELECT%201", status=200)], Config())
    assert alerts[0].severity == "critical"


def test_double_encoded_path_traversal():
    alerts = detect_web_attacks([web("/d?f=%252e%252e%252fetc%252fpasswd", status=403)], Config())
    assert alerts[0].rule == "web_path_traversal"


def test_xss():
    alerts = detect_web_attacks([web("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", status=200)], Config())
    assert {a.rule for a in alerts} == {"web_xss"}
    assert alerts[0].severity == "high"  # a 200 on XSS is not escalated


def test_sensitive_file_probe():
    alerts = detect_web_attacks([web("/.env"), web("/.git/config")], Config())
    assert alerts[0].rule == "web_sensitive_file_probe"
    assert alerts[0].count == 2


def test_benign_paths_not_flagged():
    benign = ["/", "/products?id=3", "/blog/select-the-best-union-plan", "/static/app.js",
              "/search?q=or+1+more", "/environment"]
    assert detect_web_attacks([web(p, status=200) for p in benign], Config()) == []


def test_directory_scanning():
    events = [web(f"/dir{i}/", seconds=i) for i in range(25)]
    alerts = detect_web_scanning(events, Config())
    assert alerts[0].rule == "web_directory_scanning"


def test_scanner_user_agent():
    alerts = detect_scanner_user_agents([web("/", ua="sqlmap/1.8.4#stable")], Config())
    assert "sqlmap" in alerts[0].description


# --- End to end on the bundled samples --------------------------------------

def test_samples_end_to_end():
    events, stats = parse_files([SAMPLES / "auth.log", SAMPLES / "access.log"], year=2026)
    assert stats.skipped > 0  # noise and malformed lines are skipped, not crashing
    alerts = run_all(events)
    rules = {(a.rule, a.ip) for a in alerts}
    assert ("ssh_success_after_bruteforce", "203.0.113.45") in rules
    assert ("ssh_bruteforce", "203.0.113.45") in rules
    assert ("ssh_password_spraying", "198.51.100.23") in rules
    assert ("web_directory_scanning", "192.0.2.77") in rules
    assert ("web_sql_injection", "203.0.113.99") in rules
    assert ("web_path_traversal", "198.51.100.150") in rules
    # Legitimate users must not be flagged
    assert not any(a.ip.startswith("10.0.0.") for a in alerts)
    assert alerts[0].severity == "critical"
