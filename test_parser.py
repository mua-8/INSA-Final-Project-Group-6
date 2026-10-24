import unittest
from datetime import datetime
from pathlib import Path

from backend.parser import (
    ACCEPTED_LOGIN, DISCONNECT, FAILED_LOGIN, INVALID_USER,
    MAX_FIELD_LEN, ParseError, parse_file, parse_line, parse_text,
)

YEAR = 2026
SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"


class ParseLineTests(unittest.TestCase):
    def test_failed_password(self):
        e = parse_line("Oct 24 13:00:01 web01 sshd[3001]: Failed password for root "
                       "from 203.0.113.9 port 40001 ssh2", YEAR)
        self.assertEqual(e.event_type, FAILED_LOGIN)
        self.assertEqual(e.outcome, "failure")
        self.assertEqual(e.username, "root")
        self.assertEqual(e.source_ip, "203.0.113.9")
        self.assertEqual(e.port, 40001)
        self.assertEqual(e.method, "password")
        self.assertEqual(e.host, "web01")
        self.assertEqual(e.timestamp, datetime(2026, 10, 24, 13, 0, 1))

    def test_failed_invalid_user(self):
        e = parse_line("Oct 24 13:00:13 web01 sshd[1]: Failed password for invalid "
                       "user admin from 203.0.113.9 port 40004 ssh2", YEAR)
        self.assertEqual(e.event_type, INVALID_USER)
        self.assertEqual(e.username, "admin")

    def test_invalid_user_line(self):
        e = parse_line("Oct 24 13:00:21 web01 sshd[1]: Invalid user oracle "
                       "from 203.0.113.9 port 40006", YEAR)
        self.assertEqual(e.event_type, INVALID_USER)
        self.assertEqual(e.username, "oracle")

    def test_accepted_publickey(self):
        e = parse_line("Oct 24 08:00:11 web01 sshd[1]: Accepted publickey for alice "
                       "from 10.0.0.5 port 51234 ssh2: RSA SHA256:abc", YEAR)
        self.assertEqual(e.event_type, ACCEPTED_LOGIN)
        self.assertEqual(e.outcome, "success")
        self.assertEqual(e.method, "publickey")

    def test_disconnect_variants(self):
        lines = [
            "Oct 24 09:10:02 web01 sshd[1]: Disconnected from user alice 10.0.0.5 port 51234",
            "Oct 24 09:10:02 web01 sshd[1]: Disconnected from authenticating user bob 10.0.0.6 port 1",
            "Oct 24 09:10:02 web01 sshd[1]: Received disconnect from 10.0.0.7 port 22:11: bye",
            "Oct 24 09:10:02 web01 sshd[1]: Connection closed by authenticating user bob 10.0.0.8 port 5 [preauth]",
            "Oct 24 09:10:02 web01 sshd[1]: Connection closed by 10.0.0.9 port 5 [preauth]",
        ]
        for line in lines:
            self.assertEqual(parse_line(line, YEAR).event_type, DISCONNECT, line)

    def test_ipv6_source(self):
        e = parse_line("Oct 24 13:00:01 web01 sshd[1]: Failed password for root "
                       "from 2001:db8::1 port 22 ssh2", YEAR)
        self.assertEqual(e.source_ip, "2001:db8::1")

    def test_single_digit_day_padding(self):
        e = parse_line("Oct  4 13:00:01 web01 sshd[1]: Failed password for root "
                       "from 1.2.3.4 port 22 ssh2", YEAR)
        self.assertEqual(e.timestamp.day, 4)

    def test_raw_line_preserved(self):
        raw = "Oct 24 13:00:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        self.assertEqual(parse_line(raw + "\n", YEAR).raw_line, raw)

    def test_non_sshd_line_returns_none(self):
        self.assertIsNone(parse_line(
            "Oct 24 09:12:44 web01 CRON[2210]: session opened for user root", YEAR))

    def test_unmodelled_sshd_line_returns_none(self):
        self.assertIsNone(parse_line(
            "Oct 24 09:12:44 web01 sshd[1]: Server listening on 0.0.0.0 port 22.", YEAR))

    def test_garbage_raises(self):
        with self.assertRaises(ParseError):
            parse_line("this line is garbage", YEAR)

    def test_invalid_ip_raises(self):
        with self.assertRaises(ParseError):
            parse_line("Oct 24 13:02:00 web01 sshd[1]: Failed password for bob "
                       "from 999.1.1.1 port 22 ssh2", YEAR)

    def test_invalid_date_raises(self):
        with self.assertRaises(ParseError):
            parse_line("Feb 31 13:02:00 web01 sshd[1]: Failed password for bob "
                       "from 1.2.3.4 port 22 ssh2", YEAR)

    def test_invalid_port_raises(self):
        with self.assertRaises(ParseError):
            parse_line("Oct 24 13:02:00 web01 sshd[1]: Failed password for bob "
                       "from 1.2.3.4 port 99999 ssh2", YEAR)

    def test_long_username_is_truncated(self):
        name = "a" * 500
        e = parse_line(f"Oct 24 13:00:01 web01 sshd[1]: Invalid user {name} "
                       "from 1.2.3.4 port 22", YEAR)
        self.assertEqual(len(e.username), MAX_FIELD_LEN)

    def test_hostile_username_kept_as_plain_text(self):
        e = parse_line("Oct 24 13:00:01 web01 sshd[1]: Invalid user <script>alert(1)</script>"
                       " from 1.2.3.4 port 22", YEAR)
        # Parser stores it verbatim; escaping is the dashboard's job (RSD slide 13)
        self.assertEqual(e.username, "<script>alert(1)</script>")

    def test_overlong_line_raises(self):
        with self.assertRaises(ParseError):
            parse_line("Oct 24 13:00:01 web01 sshd[1]: " + "x" * 5000, YEAR)


class ParseBatchTests(unittest.TestCase):
    def test_malformed_lines_counted_not_fatal(self):
        text = (
            "garbage\n"
            "Oct 24 13:00:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
            "\n"
            "Oct 24 13:00:02 web01 sshd[1]: Failed password for root from 999.9.9.9 port 22 ssh2\n"
        )
        r = parse_text(text, YEAR)
        self.assertEqual(len(r.events), 1)
        self.assertEqual(r.malformed_count, 2)
        self.assertEqual(r.total_lines, 3)       # blank lines are not counted
        self.assertEqual([n for n, _ in r.errors], [1, 4])

    def test_duplicates_skipped(self):
        line = "Oct 24 13:00:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        r = parse_text(f"{line}\n{line}\n", YEAR)
        self.assertEqual(len(r.events), 1)
        self.assertEqual(r.duplicate_count, 1)

    def test_duplicates_kept_when_disabled(self):
        line = "Oct 24 13:00:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        r = parse_text(f"{line}\n{line}\n", YEAR, skip_duplicates=False)
        self.assertEqual(len(r.events), 2)

    def test_baseline_file(self):
        r = parse_file(str(SAMPLES / "baseline.log"), YEAR)
        self.assertEqual(r.malformed_count, 0)
        self.assertEqual(r.skipped_count, 1)     # the CRON line
        self.assertEqual(len(r.events), 4)

    def test_brute_force_file(self):
        r = parse_file(str(SAMPLES / "brute_force.log"), YEAR)
        self.assertEqual(len(r.events), 7)
        self.assertEqual(r.malformed_count, 2)   # garbage + bad IP
        failures = [e for e in r.events if e.outcome == "failure"]
        self.assertEqual(len(failures), 6)

    def test_binary_junk_does_not_crash(self):
        path = SAMPLES / "_junk.tmp"
        path.write_bytes(b"\xff\xfe\x00\x01 not text \x80\n")
        try:
            r = parse_file(str(path), YEAR)
            self.assertEqual(r.malformed_count, 1)
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
