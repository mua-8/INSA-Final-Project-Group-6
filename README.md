# ThreatLens - SSH Log Parser (individual contribution)

Parses OpenSSH authentication log lines into structured events
(RSD requirements FR-02 to FR-06, Phase 2 of the roadmap).

## Run the tests
```bash
python -m unittest discover -s tests -v
```

## Try it on a sample log
```bash
python -m backend.parser sample_logs/brute_force.log 2026
```

## What it extracts
time, host, source IP, port, username, auth method, event type
(`failed_login`, `invalid_user`, `accepted_login`, `disconnect`), outcome,
and the raw line.

## Security notes
- Source IPs are validated; ports are range-checked.
- Usernames/hosts are length-limited (attackers control them).
- Malformed lines are counted and reported, never fatal.
- The parser stores text as-is; the dashboard must escape it when displaying.
