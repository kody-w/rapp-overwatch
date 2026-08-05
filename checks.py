#!/usr/bin/env python3
"""checks.py — what "the sentinel is slipping" actually looks like, in files.

Every check answers a question about the SUBJECT and reads primary evidence to
do it. Where the subject publishes its own conclusion about something we can
observe directly, we observe it directly and then compare — a disagreement
between what it reports and what we measure is itself one of the findings.

Grouped by twin. The grouping is not cosmetic: each twin emits its own frame
carrying only its own results, so a compromised or wrong twin cannot launder a
verdict through the other two.

Ordering note for anyone adding a check: it must be possible to make it FAIL on
purpose. A check nobody has ever seen fire is indistinguishable from a check
that cannot fire, and this project exists because of two such checks.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

CRITICAL = "critical"
WARN = "warn"

HOME = Path(__file__).resolve().parent


def _state_dir() -> Path:
    """Overridable so the negative tests can prove a guard fires without
    polluting (or being polluted by) the real observation history."""
    return Path(os.environ.get("OVERWATCH_STATE", str(HOME / "state")))


STATE = _state_dir()
OBSERVATIONS = STATE / "observations.jsonl"
BASELINE = STATE / "baseline.json"


def ok(cid, detail):
    return {"id": cid, "ok": True, "severity": WARN, "detail": detail}


def fail(cid, detail, critical=False):
    return {"id": cid, "ok": False,
            "severity": CRITICAL if critical else WARN, "detail": detail}


def direction():
    p = Path(os.environ.get("OVERWATCH_DIRECTION", str(HOME / "direction.json")))
    return json.loads(p.read_text(encoding="utf-8"))


def subject_root() -> Path:
    env = os.environ.get("OVERWATCH_SUBJECT_ROOT")
    if env:
        return Path(os.path.expanduser(env))
    cfg = json.loads((HOME / "config.json").read_text(encoding="utf-8"))
    return Path(os.path.expanduser(cfg.get("subject_root", "~/rapp-sentinel")))


def _load(p: Path):
    """Read JSON, distinguishing 'absent' from 'present but broken'.

    Returns (value, error). A missing file is not an error for every caller —
    several checks must treat absence as the finding rather than as a crash.
    """
    if not p.exists():
        return None, "missing"
    try:
        return json.loads(p.read_text(encoding="utf-8")), None
    except Exception as exc:
        return None, f"unparseable: {type(exc).__name__}: {exc}"


def _age_minutes(ts: str):
    try:
        t = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - t).total_seconds() / 60
    except Exception:
        return None


# ── ledger: are its claims backed by evidence we gathered? ───────────────────

def l_chains_verify():
    """Re-verify every one of the subject's chains from genesis, ourselves."""
    import twins
    heads = twins.subject_heads(subject_root())
    if not heads:
        return fail("l_chains_verify", "subject has no readable chains", critical=True)
    bad = [f"{s}: {h.get('detail')}" for s, h in heads.items()
           if not h.get("readable") or not h.get("chain_ok")]
    if bad:
        return fail("l_chains_verify", "; ".join(bad), critical=True)
    total = sum(h.get("frames", 0) for h in heads.values())
    return ok("l_chains_verify",
              f"{len(heads)} chains, {total} frames verified from genesis")


def l_no_rewind():
    """Did the subject's history move under us since we first witnessed it?

    This is the one thing the subject structurally cannot check about itself:
    its anchor file lives inside the directory it attests, so whatever could
    rewrite a chain could rewrite the witness too.
    """
    import twins
    rep = twins.subject_rewind(subject_root())
    if not rep:
        return ok("l_no_rewind", "no prior witness yet (first run)")
    bad = [f"{s}: {v['detail']} (witnessed {v['witnessed_seq']}, now {v['current_seq']})"
           for s, v in rep.items() if v.get("truncated") or v.get("rewritten")]
    if bad:
        return fail("l_no_rewind", "; ".join(bad), critical=True)
    return ok("l_no_rewind", f"{len(rep)} chains match every head we witnessed")


def l_selfreport_agrees():
    """Compare the subject's own integrity claim against our measurement.

    It publishes state/anchors.json saying whether its chains were truncated.
    We computed the same thing independently. Agreement is unremarkable;
    disagreement means one of us is wrong about tamper-evidence, which is worth
    waking someone for either way.
    """
    import twins
    claim, err = _load(subject_root() / "state" / "anchors.json")
    if err:
        return fail("l_selfreport_agrees", f"subject anchors.json {err}")
    ours = twins.subject_rewind(subject_root())
    if not ours:
        return ok("l_selfreport_agrees", "no prior witness yet (first run)")
    disputes = []
    for slug, mine in ours.items():
        theirs = (claim or {}).get(slug)
        if theirs is None:
            disputes.append(f"{slug}: subject does not report on a chain we can see")
            continue
        if bool(theirs.get("truncated")) != bool(mine.get("truncated")):
            disputes.append(f"{slug}: subject says truncated={theirs.get('truncated')}, "
                            f"we measured {mine.get('truncated')}")
    if disputes:
        return fail("l_selfreport_agrees", "; ".join(disputes), critical=True)
    return ok("l_selfreport_agrees", f"subject's integrity claim matches ours on {len(ours)} chains")


def l_verdict_backed():
    """A 'healthy' verdict is only a claim about the moment it was written."""
    d = direction()["thresholds"]
    verdict, verr = _load(subject_root() / "state" / "last_verdict.json")
    run, rerr = _load(subject_root() / "state" / "last_run.json")
    if verr and rerr:
        return fail("l_verdict_backed", f"no verdict ({verr}) and no run record ({rerr})",
                    critical=True)
    src = run or verdict or {}
    at = src.get("at") or src.get("generated")
    age = _age_minutes(at) if at else None
    if age is None:
        return fail("l_verdict_backed", "verdict carries no readable timestamp")
    status = (run or {}).get("status") or (verdict or {}).get("status") or "unknown"
    if status == "healthy" and age > d["tick_stale_minutes"]:
        return fail("l_verdict_backed",
                    f"serving 'healthy' from a verdict {age:.0f}m old "
                    f"(stale past {d['tick_stale_minutes']}m)", critical=True)
    return ok("l_verdict_backed", f"verdict '{status}' is {age:.0f}m old")


# ── compass: does its declared goal still match the world? ───────────────────

def c_coverage():
    """What it says it watches, against what this ecosystem now contains."""
    dj, err = _load(subject_root() / "direction.json")
    if err:
        return fail("c_coverage", f"subject direction.json {err}", critical=True)
    watched = set(dj.get("cares_about") or [])
    expected = set(direction().get("expected_coverage") or [])
    missing = sorted(expected - watched)
    if not watched:
        return fail("c_coverage", "subject declares no repositories at all", critical=True)
    if missing:
        return fail("c_coverage",
                    f"watches {len(watched)}/{len(expected)} expected; "
                    f"uncovered: {', '.join(r.split('/')[-1] for r in missing)}")
    return ok("c_coverage", f"covers all {len(expected)} expected repositories")


def c_config_agrees():
    """Two files declare the watch list. They are allowed to disagree silently."""
    dj, derr = _load(subject_root() / "direction.json")
    cj, cerr = _load(subject_root() / "config.json")
    if derr or cerr:
        return fail("c_config_agrees", f"direction.json {derr}; config.json {cerr}")
    a = set(dj.get("cares_about") or [])
    b = set(cj.get("watch_repos") or [])
    if a != b:
        only_d, only_c = sorted(a - b), sorted(b - a)
        return fail("c_config_agrees",
                    f"direction.cares_about and config.watch_repos disagree — "
                    f"only in direction: {only_d or 'none'}; only in config: {only_c or 'none'}")
    return ok("c_config_agrees", f"both declarations list the same {len(a)} repositories")


def c_boundaries_intact():
    """Boundaries may be added. A boundary that disappears is the finding."""
    dj, err = _load(subject_root() / "direction.json")
    if err:
        return fail("c_boundaries_intact", f"subject direction.json {err}", critical=True)
    now = [str(b) for b in (dj.get("boundaries") or [])]
    base, berr = _load(BASELINE)
    if berr or "boundaries" not in (base or {}):
        STATE.mkdir(parents=True, exist_ok=True)
        merged = dict(base or {})
        merged["boundaries"] = now
        merged["recorded_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        BASELINE.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
        return ok("c_boundaries_intact", f"baseline recorded: {len(now)} boundaries")
    dropped = [b for b in base["boundaries"] if b not in now]
    if dropped:
        return fail("c_boundaries_intact",
                    f"{len(dropped)} boundary/boundaries removed since baseline: "
                    + " | ".join(d[:60] for d in dropped), critical=True)
    added = len(now) - len(base["boundaries"])
    return ok("c_boundaries_intact",
              f"all {len(base['boundaries'])} baseline boundaries intact"
              + (f" (+{added} added)" if added > 0 else ""))


def c_direction_fresh():
    """A goal written once and never revisited stops describing the world."""
    dj, err = _load(subject_root() / "direction.json")
    if err:
        return fail("c_direction_fresh", f"subject direction.json {err}")
    age = _age_minutes(dj.get("updated_at"))
    if age is None:
        return fail("c_direction_fresh", "direction.json has no readable updated_at")
    days = age / 1440
    limit = direction()["thresholds"]["direction_stale_days"]
    if days > limit:
        return fail("c_direction_fresh",
                    f"direction unchanged for {days:.0f}d (limit {limit}d)")
    return ok("c_direction_fresh", f"direction updated {days:.1f}d ago")


# ── pulse: is work still moving? ─────────────────────────────────────────────

def p_tick_fresh():
    """Measured from its own state file, not from asking it."""
    run, err = _load(subject_root() / "state" / "last_run.json")
    if err:
        return fail("p_tick_fresh", f"subject last_run.json {err}", critical=True)
    age = _age_minutes(run.get("at"))
    if age is None:
        return fail("p_tick_fresh", "last_run.json has no readable timestamp")
    limit = direction()["thresholds"]["tick_stale_minutes"]
    if age > limit:
        return fail("p_tick_fresh", f"last tick {age:.0f}m ago (limit {limit}m)",
                    critical=True)
    return ok("p_tick_fresh", f"last tick {age:.0f}m ago")


def p_green_streak():
    """Permanent green is the shape both of its historical failures had.

    Not a failure on its own — a quiet week is a real thing. It is reported
    once the streak is long enough that "nothing is wrong" and "nothing is
    being checked" have become indistinguishable from out here, which is
    exactly the question this whole project was stood up to ask.
    """
    obs = []
    if OBSERVATIONS.exists():
        for line in OBSERVATIONS.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    obs.append(json.loads(line))
                except Exception:
                    continue
    streak = 0
    for o in reversed(obs):
        if o.get("subject_status") == "healthy":
            streak += 1
        else:
            break
    limit = direction()["thresholds"]["green_streak_suspicious"]
    esc, _ = _load(subject_root() / "state" / "escalations.json")
    last_esc_age = None
    if isinstance(esc, list) and esc:
        last_esc_age = _age_minutes(esc[-1].get("at"))
    if streak >= limit:
        detail = f"{streak} consecutive healthy observations"
        if last_esc_age is not None:
            detail += f"; last escalation {last_esc_age/1440:.1f}d ago"
        return fail("p_green_streak", detail + " — verify a check can still fail")
    return ok("p_green_streak", f"{streak} consecutive healthy (limit {limit})")


def p_checks_nonvacuous():
    """A check that silently stops being registered takes its coverage with it.

    We record which check IDs the subject ran. An ID that used to appear and
    then stops is scope lost without a decision — the same class of defect as a
    liveness probe that never touched the endpoint, one level up.
    """
    verdict, err = _load(subject_root() / "state" / "last_verdict.json")
    if err:
        return fail("p_checks_nonvacuous", f"subject last_verdict.json {err}")
    ids = sorted({c.get("id") for c in (verdict.get("checks") or []) if c.get("id")})
    if not ids:
        return fail("p_checks_nonvacuous", "subject's last verdict ran no checks at all",
                    critical=True)
    base, berr = _load(BASELINE)
    base = base or {}
    known = set(base.get("check_ids") or [])
    if berr or not known:
        STATE.mkdir(parents=True, exist_ok=True)
        base["check_ids"] = ids
        base.setdefault("recorded_utc",
                        datetime.now(timezone.utc).isoformat(timespec="seconds"))
        BASELINE.write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
        return ok("p_checks_nonvacuous", f"baseline recorded: {len(ids)} checks")
    vanished = sorted(known - set(ids))
    if vanished:
        return fail("p_checks_nonvacuous",
                    f"{len(vanished)} check(s) no longer run: {', '.join(vanished)}",
                    critical=True)
    new = sorted(set(ids) - known)
    if new:
        base["check_ids"] = sorted(set(ids) | known)
        BASELINE.write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
    return ok("p_checks_nonvacuous",
              f"all {len(known)} known checks still run" + (f" (+{len(new)} new)" if new else ""))


def p_daemons_loaded():
    """launchd jobs, read from launchd — including the loaded-without-pid case.

    'Loaded' is a substring of `launchctl list` and nothing more. The subject
    learned this about openrappter's daemon and fixed it there; the same
    predicate applies to its own jobs, so it is asked here rather than assumed.
    Periodic jobs legitimately sit with no pid between runs, so a missing pid is
    only reported alongside a non-zero last exit status.
    """
    want = direction().get("launchd_labels") or [
        "com.rapp.neighborhood-watch", "com.rapp.nightwatch"]
    try:
        r = subprocess.run(["launchctl", "list"], capture_output=True, text=True, timeout=15)
    except Exception as exc:
        return fail("p_daemons_loaded", f"launchctl unavailable: {type(exc).__name__}")
    rows = {}
    for line in (r.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            rows[parts[2].strip()] = (parts[0].strip(), parts[1].strip())
    problems = []
    for label in want:
        if label not in rows:
            problems.append(f"{label}: not loaded")
            continue
        pid, status = rows[label]
        if status not in ("0", "-"):
            problems.append(f"{label}: last exit status {status}")
    if problems:
        return fail("p_daemons_loaded", "; ".join(problems))
    return ok("p_daemons_loaded", f"{len(want)} launchd jobs loaded, last exit clean")


BY_TWIN = {
    "ledger":  [l_chains_verify, l_no_rewind, l_selfreport_agrees, l_verdict_backed],
    "compass": [c_coverage, c_config_agrees, c_boundaries_intact, c_direction_fresh],
    "pulse":   [p_tick_fresh, p_green_streak, p_checks_nonvacuous, p_daemons_loaded],
}


def all_checks():
    for fns in BY_TWIN.values():
        yield from fns
