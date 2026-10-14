from datetime import datetime

from loghunter.parsers import parse_lines, parse_ssh_line, parse_web_line


def test_ssh_failed_password():
    e = parse_ssh_line("Oct 12 03:14:07 srv sshd[123]: Failed password for root "
                       "from 203.0.113.45 port 52344 ssh2", year=2026)
    assert e.action == "ssh_failed"
    assert e.user == "root"
    assert e.ip == "203.0.113.45"
    assert e.timestamp == datetime(2026, 10, 12, 3, 14, 7)


def test_ssh_failed_invalid_user_single_digit_day():
    e = parse_ssh_line("Oct  2 03:14:07 srv sshd[123]: Failed password for invalid user "
                       "admin from 198.51.100.23 port 52344 ssh2", year=2026)
    assert e.action == "ssh_failed"
    assert e.user == "admin"
    assert e.timestamp.day == 2


def test_ssh_accepted_publickey():
    e = parse_ssh_line("Oct 12 09:00:00 srv sshd[9]: Accepted publickey for alice "
                       "from 10.0.0.12 port 50000 ssh2: ED25519 SHA256:abc", year=2026)
    assert e.action == "ssh_accepted"
    assert e.user == "alice"


def test_ssh_invalid_user():
    e = parse_ssh_line("Oct 12 09:00:00 srv sshd[9]: Invalid user oracle from "
                       "198.51.100.23 port 4444", year=2026)
    assert e.action == "ssh_invalid_user"
    assert e.user == "oracle"


def test_ssh_iso_timestamp_converted_to_utc():
    e = parse_ssh_line("2026-10-12T04:14:07.123456+01:00 srv sshd[1]: Failed password "
                       "for root from 2001:db8::1 port 22 ssh2")
    assert e.timestamp == datetime(2026, 10, 12, 3, 14, 7, 123456)
    assert e.ip == "2001:db8::1"


def test_ssh_irrelevant_lines_ignored():
    assert parse_ssh_line("Oct 12 09:00:00 srv sshd[9]: pam_unix(sshd:session): "
                          "session opened for user alice", year=2026) is None
    assert parse_ssh_line("Oct 12 09:00:00 srv CRON[9]: (root) CMD (run-parts)") is None


def test_web_combined_line():
    e = parse_web_line('192.0.2.77 - - [12/Oct/2026:11:00:03 +0200] "GET /.env HTTP/1.1" '
                       '404 153 "-" "Mozilla/5.00 (Nikto/2.5.0)"')
    assert e.source == "web"
    assert e.path == "/.env"
    assert e.status == 404
    assert "Nikto" in e.user_agent
    assert e.timestamp == datetime(2026, 10, 12, 9, 0, 3)  # normalised to UTC


def test_web_common_format_without_user_agent():
    e = parse_web_line('10.0.0.1 - - [12/Oct/2026:11:00:03 +0000] "POST /login HTTP/1.0" 200 -')
    assert e.method == "POST"
    assert e.user_agent is None


def test_malformed_web_line_skipped():
    assert parse_web_line('192.0.2.200 - - [12/Oct/2026:08:00:00 +0000] "\\x16\\x03\\x01" '
                          '400 157 "-" "-"') is None


def test_parse_lines_mixed_formats():
    lines = [
        "Oct 12 03:14:07 srv sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        '1.2.3.4 - - [12/Oct/2026:03:14:08 +0000] "GET / HTTP/1.1" 200 10 "-" "curl/8"',
        "garbage",
    ]
    events = parse_lines(lines, year=2026)
    assert [e.source for e in events] == ["ssh", "web"]
