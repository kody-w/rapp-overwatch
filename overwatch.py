#!/usr/bin/env python3
"""overwatch.py — one tick: observe the subject, record it, say what changed.

    python3 overwatch.py tick        # run checks, emit three frames, anchor
    python3 overwatch.py verdict     # run checks, print, emit nothing
    python3 overwatch.py report      # one paragraph fit for a text message

A tick is deliberately cheap and invokes no model. It reads files, verifies
hashes, and appends. The expensive judgement — deciding what a finding MEANS —
is left to whoever reads the report, because a watcher that reasons about its
subject on every tick is a watcher with a budget, and a budget is a reason to
skip a tick.

Nothing here writes to the subject. That is a boundary in direction.json and
also just the design: every path below opens the subject read-only.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import checks as C
import twins

HOME = Path(__file__).resolve().parent
STATE = HOME / "state"


def run_checks():
    """Run every check, grouped by the twin that owns it.

    A check that raises is a broken check, not a broken subject, and is
    reported as such — conflating the two is how a monitoring bug becomes an
    outage report at three in the morning.
    """
    by_twin, flat = {}, []
    for twin, fns in C.BY_TWIN.items():
        results = []
        for fn in fns:
            try:
                r = fn()
                if not isinstance(r, dict):
                    r = C.fail(fn.__name__, "check returned a non-result")
            except Exception as exc:
                r = C.fail(fn.__name__, f"check raised {type(exc).__name__}: {exc}")
            results.append(r)
        by_twin[twin] = results
        flat += results
    return by_twin, flat


def verdict(by_twin, flat):
    failed = [c for c in flat if not c["ok"]]
    crit = [c for c in failed if c["severity"] == C.CRITICAL]
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subject": str(C.subject_root()),
        "status": "critical" if crit else ("degraded" if failed else "healthy"),
        "by_twin": {t: {"failed": [c["id"] for c in rs if not c["ok"]],
                        "passed": [c["id"] for c in rs if c["ok"]]}
                    for t, rs in by_twin.items()},
        "checks": flat,
        "failed": [c["id"] for c in failed],
        "critical": [c["id"] for c in crit],
        "summary": "; ".join(f"{c['id']}: {c['detail']}" for c in failed) or "no slip detected",
    }


def _subject_status():
    """The subject's own current verdict, for streak accounting."""
    run, err = C._load(C.subject_root() / "state" / "last_run.json")
    return (run or {}).get("status", "unknown") if not err else "unreadable"


def tick():
    by_twin, flat = run_checks()
    v = verdict(by_twin, flat)

    # Witness the subject BEFORE emitting our own frames. If the subject's
    # history has been spliced, we want that recorded even if a later step
    # here fails.
    twins.witness_subject(C.subject_root())

    for twin, results in by_twin.items():
        failed = [c["id"] for c in results if not c["ok"]]
        twins.emit(twin, "overwatch.observation", {
            "twin": twin,
            "vantage": twins.TWINS[twin],
            "subject": v["subject"],
            "status": "degraded" if failed else "healthy",
            "failed": failed,
            "findings": [{"id": c["id"], "ok": c["ok"], "detail": c["detail"]}
                         for c in results],
        })
    twins.anchor_heads()

    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / "last_verdict.json").write_text(json.dumps(v, indent=2) + "\n",
                                             encoding="utf-8")
    with open(STATE / "observations.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": v["generated"], "status": v["status"],
                             "failed": v["failed"],
                             "subject_status": _subject_status()}) + "\n")
    return v


def report(v):
    """What a person needs at 3am, and nothing else."""
    rc = twins.roll_call()
    lines = []
    if v["status"] == "healthy":
        lines.append("Overwatch: sentinel not slipping. "
                     f"{len(v['checks'])} checks across 3 twins, all pass.")
    else:
        lines.append(f"Overwatch: sentinel {v['status'].upper()}.")
        for c in v["checks"]:
            if not c["ok"]:
                mark = "!!" if c["severity"] == C.CRITICAL else "-"
                lines.append(f"{mark} {c['id']}: {c['detail']}")
    stalled = [s for s, r in rc.items() if not r["alive"] and r["frames"] > 0]
    broken = [s for s, r in rc.items() if not r["chain_ok"]]
    if broken:
        lines.append(f"OUR OWN chains failed to verify: {', '.join(broken)}")
    elif stalled:
        lines.append(f"our twins stalled: {', '.join(stalled)}")
    return "\n".join(lines)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "tick"
    if cmd == "verdict":
        by_twin, flat = run_checks()
        print(json.dumps(verdict(by_twin, flat), indent=2))
    elif cmd == "tick":
        print(json.dumps(tick(), indent=2))
    elif cmd == "report":
        by_twin, flat = run_checks()
        print(report(verdict(by_twin, flat)))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
