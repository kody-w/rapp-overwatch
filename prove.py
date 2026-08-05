#!/usr/bin/env python3
"""prove.py — make every guard fire on purpose, then confirm it goes quiet.

    python3 prove.py

This exists because of a specific, repeated failure in the system being
watched: a liveness probe that attested "alive" fourteen times without ever
touching the endpoint it was supposed to test, and a guardian that exited 0 for
five days while unauthenticated. Neither was caught by reading the code. Both
would have been caught by trying to make them fail once.

So each scenario below deliberately slips a THROWAWAY COPY of the subject and
asserts the matching check fails, then asserts the same check passes on a clean
copy. Both halves matter: a check that fails on everything is as useless as one
that fails on nothing, and only the pair distinguishes them.

The real ~/rapp-sentinel is never modified. Every scenario copies it first.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOME = Path(__file__).resolve().parent
REAL_SUBJECT = Path(os.path.expanduser("~/rapp-sentinel"))

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def run_check(name, subject, state, nbhd, direction=None):
    """Run ONE check in a subprocess with its own state, so scenarios cannot
    contaminate each other through a shared baseline file."""
    env = dict(os.environ,
               OVERWATCH_SUBJECT_ROOT=str(subject),
               OVERWATCH_STATE=str(state),
               OVERWATCH_NBHD=str(nbhd))
    if direction:
        env["OVERWATCH_DIRECTION"] = str(direction)
    code = (f"import json,checks; r=checks.{name}(); print(json.dumps(r))")
    r = subprocess.run([sys.executable, "-c", code], cwd=HOME, env=env,
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return {"id": name, "ok": None, "detail": f"harness error: {r.stderr.strip()[-300:]}"}
    return json.loads(r.stdout.strip().splitlines()[-1])


def fresh_copy(tmp, tag):
    """A throwaway subject, plus empty state and neighborhood for the watcher."""
    subject = Path(tmp) / f"{tag}-subject"
    shutil.copytree(REAL_SUBJECT, subject,
                    ignore=shutil.ignore_patterns("__pycache__", ".git", "logs"))
    state = Path(tmp) / f"{tag}-state"
    nbhd = Path(tmp) / f"{tag}-nbhd"
    state.mkdir(parents=True, exist_ok=True)
    nbhd.mkdir(parents=True, exist_ok=True)
    # Keep the subject fresh so unrelated staleness checks do not fire and
    # confuse which guard the scenario actually proved.
    now = datetime.now(timezone.utc)
    _write(subject / "state" / "last_run.json",
           {"at": now.isoformat(), "status": "healthy", "failed": [],
            "summary": "all checks passing"})
    return subject, state, nbhd


def _write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def _read(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def _witness(subject, state, nbhd):
    """Record the subject's heads in our witness, as a real tick would."""
    env = dict(os.environ, OVERWATCH_SUBJECT_ROOT=str(subject),
               OVERWATCH_STATE=str(state), OVERWATCH_NBHD=str(nbhd))
    code = ("import twins,pathlib,os;"
            "twins.witness_subject(pathlib.Path(os.environ['OVERWATCH_SUBJECT_ROOT']))")
    subprocess.run([sys.executable, "-c", code], cwd=HOME, env=env,
                   capture_output=True, text=True, timeout=120)


def _first_chain(subject: Path):
    for d in sorted((subject / "neighborhood").iterdir()):
        if d.is_dir() and (d / "chain.jsonl").exists():
            return d / "chain.jsonl"
    raise RuntimeError("no chain found in subject copy")


# ── scenarios: (check, description, slip function) ───────────────────────────

def slip_corrupt_frame(subject, state, nbhd):
    cf = _first_chain(subject)
    lines = cf.read_text(encoding="utf-8").splitlines()
    fr = json.loads(lines[len(lines) // 2])
    fr["payload"] = dict(fr.get("payload") or {}, tampered=True)
    lines[len(lines) // 2] = json.dumps(fr)
    cf.write_text("\n".join(lines) + "\n", encoding="utf-8")


def slip_truncate(subject, state, nbhd):
    _witness(subject, state, nbhd)          # witness the tall chain first
    cf = _first_chain(subject)
    lines = cf.read_text(encoding="utf-8").splitlines()
    cf.write_text("\n".join(lines[:-5]) + "\n", encoding="utf-8")


def slip_truncate_and_deny(subject, state, nbhd):
    slip_truncate(subject, state, nbhd)
    anchors = subject / "state" / "anchors.json"
    claim = _read(anchors) if anchors.exists() else {}
    for slug in claim:
        claim[slug]["truncated"] = False    # subject insists all is well
    _write(anchors, claim)


def slip_stale_healthy_verdict(subject, state, nbhd):
    old = (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat()
    _write(subject / "state" / "last_run.json",
           {"at": old, "status": "healthy", "failed": [], "summary": "all checks passing"})


def _coverage_direction(subject, state):
    """An overwatch direction whose expectation matches what the subject
    currently watches — so the clean run passes and only the narrowing fires.

    Without this the scenario proves nothing: c_coverage already fails against
    the real sentinel (it watches 2 of 11), so a slipped copy failing too would
    be indistinguishable from the check being stuck on.
    """
    d = _read(HOME / "direction.json")
    d["expected_coverage"] = list(_read(subject / "direction.json").get("cares_about") or [])
    _write(Path(state) / "direction.json", d)


def prep_coverage(subject, state, nbhd):
    _coverage_direction(subject, state)


def slip_narrow_scope(subject, state, nbhd):
    _coverage_direction(subject, state)
    d = _read(subject / "direction.json")
    d["cares_about"] = ["kody-w/rappterverse"]
    _write(subject / "direction.json", d)


def slip_config_disagrees(subject, state, nbhd):
    c = _read(subject / "config.json")
    c["watch_repos"] = ["kody-w/rappterverse"]
    _write(subject / "config.json", c)


def slip_drop_boundary(subject, state, nbhd):
    run_check("c_boundaries_intact", subject, state, nbhd)   # record baseline
    d = _read(subject / "direction.json")
    d["boundaries"] = d["boundaries"][:-1]
    _write(subject / "direction.json", d)


def slip_stale_direction(subject, state, nbhd):
    d = _read(subject / "direction.json")
    d["updated_at"] = (datetime.now(timezone.utc) - timedelta(days=90)
                       ).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write(subject / "direction.json", d)


def slip_stale_tick(subject, state, nbhd):
    old = (datetime.now(timezone.utc) - timedelta(hours=9)).isoformat()
    _write(subject / "state" / "last_run.json",
           {"at": old, "status": "healthy", "failed": [], "summary": "all checks passing"})


def slip_endless_green(subject, state, nbhd):
    with open(Path(state) / "observations.jsonl", "w", encoding="utf-8") as fh:
        for _ in range(200):
            fh.write(json.dumps({"at": "2026-08-01T00:00:00Z", "status": "healthy",
                                 "failed": [], "subject_status": "healthy"}) + "\n")


def slip_check_vanished(subject, state, nbhd):
    run_check("p_checks_nonvacuous", subject, state, nbhd)   # record baseline
    v = _read(subject / "state" / "last_verdict.json")
    v["checks"] = (v.get("checks") or [])[:-3]               # three stop running
    _write(subject / "state" / "last_verdict.json", v)


def slip_daemon_missing(subject, state, nbhd):
    """Point the check at a label that is certainly not loaded."""
    d = _read(HOME / "direction.json")
    d["launchd_labels"] = ["com.rapp.this-job-does-not-exist"]
    _write(Path(state) / "direction.json", d)


def prep_declared_only(subject, state, nbhd):
    """Expect exactly what the subject declares, so only the cheat can fire."""
    _coverage_direction(subject, state)


def slip_declared_not_checked(subject, state, nbhd):
    """The cheat this guard exists to refuse: satisfy coverage by editing a list.

    cares_about is read by no code and watch_repos only by the dashboard, so
    appending a name widens the DECLARATION and watches nothing. An earlier
    version of c_coverage compared two lists and would have gone green here.
    """
    d = _read(subject / "direction.json")
    d["cares_about"] = list(d.get("cares_about") or []) + ["kody-w/not-actually-watched"]
    _write(subject / "direction.json", d)
    ow = _read(HOME / "direction.json")
    ow["expected_coverage"] = list(d["cares_about"])   # expectation satisfied on paper
    _write(Path(state) / "direction.json", ow)


SCENARIOS = [
    ("l_chains_verify",     "an interior frame payload is rewritten",        slip_corrupt_frame, None),
    ("l_no_rewind",         "five frames are dropped after we witnessed them", slip_truncate, None),
    ("l_selfreport_agrees", "subject is truncated but reports truncated=false", slip_truncate_and_deny, None),
    ("l_verdict_backed",    "'healthy' served from a 12h-old verdict",       slip_stale_healthy_verdict, None),
    ("c_coverage",          "declared scope narrows to one repository",      slip_narrow_scope, prep_coverage),
    ("c_coverage",          "scope is widened by declaration only, no check", slip_declared_not_checked, prep_declared_only),
    ("c_config_agrees",     "config.watch_repos drifts from direction",      slip_config_disagrees, None),
    ("c_boundaries_intact", "a boundary is quietly deleted",                 slip_drop_boundary, None),
    ("c_direction_fresh",   "direction untouched for 90 days",               slip_stale_direction, None),
    ("p_tick_fresh",        "the loop stopped ticking 9h ago",               slip_stale_tick, None),
    ("p_green_streak",      "200 consecutive healthy observations",          slip_endless_green, None),
    ("p_checks_nonvacuous", "three checks silently stop being registered",   slip_check_vanished, None),
    ("p_daemons_loaded",    "a watched launchd job is not loaded",           slip_daemon_missing, None),
]


def main():
    if not REAL_SUBJECT.is_dir():
        print(f"subject not found: {REAL_SUBJECT}")
        return 2

    print(f"prove.py — every guard must be seen firing\n{'=' * 74}")
    passed = failed = 0
    with tempfile.TemporaryDirectory(prefix="overwatch-prove-") as tmp:
        for i, (name, desc, slip, prep) in enumerate(SCENARIOS):
            # Tag by index, not by check name: one check can own several
            # scenarios (c_coverage has two -- narrowed, and widened by
            # declaration only) and name-based temp dirs collided.
            tag = f"{i:02d}-{name}"
            # 1. clean copy: the check must PASS, or the scenario proves nothing
            s, st, nb = fresh_copy(tmp, f"{tag}-clean")
            if prep:
                prep(s, st, nb)
            cdj = Path(st) / "direction.json"
            clean = run_check(name, s, st, nb, direction=cdj if cdj.exists() else None)

            # 2. slipped copy: the same check must FAIL
            s2, st2, nb2 = fresh_copy(tmp, f"{tag}-slip")
            slip(s2, st2, nb2)
            dj = Path(st2) / "direction.json"
            slipped = run_check(name, s2, st2, nb2,
                                direction=dj if dj.exists() else None)

            good = clean.get("ok") is True and slipped.get("ok") is False
            passed, failed = (passed + 1, failed) if good else (passed, failed + 1)
            mark = f"{GREEN}FIRES{RESET}" if good else f"{RED}BROKEN{RESET}"
            print(f"  [{mark}] {name}")
            print(f"{DIM}          when: {desc}{RESET}")
            if good:
                print(f"{DIM}          said: {slipped['detail'][:96]}{RESET}")
            else:
                print(f"          clean -> ok={clean.get('ok')} {clean.get('detail','')[:70]}")
                print(f"          slip  -> ok={slipped.get('ok')} {slipped.get('detail','')[:70]}")

    print("=" * 74)
    print(f"  {passed}/{len(SCENARIOS)} guards proven to fire and then go quiet")
    if failed:
        print(f"  {RED}{failed} guard(s) did not distinguish a slipped subject "
              f"from a clean one.{RESET}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
