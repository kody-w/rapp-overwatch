#!/usr/bin/env python3
"""twins.py — an independent three-twin neighborhood that watches a sentinel.

Deliberately standalone. It shares the `rapp/1` frame format with
kody-w/rapp-sentinel (vendored in rapp.py, authority kody-w/rapp-1) and shares
nothing else: its own identities, its own chains, its own anchor file, its own
launchd job. If the sentinel's whole directory were deleted, every frame here
would still verify.

That independence is the entire point. A watcher that stores its findings
inside the thing it watches can be silenced by the thing it watches.

Three twins, three vantages on the same question — "is the sentinel still doing
what it said it would?" They are separated because the failure modes are
genuinely different, and a single check that mixes them reports one verdict for
three unrelated reasons:

  ledger   — are its CLAIMS backed by evidence we gathered ourselves?
  compass  — does its declared GOAL still match the world it operates in?
  pulse    — is work still MOVING, or has it settled into permanent green?
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import rapp

HOME = Path(__file__).resolve().parent
NBHD = Path(os.environ.get("OVERWATCH_NBHD", str(HOME / "neighborhood")))
ANCHORS = NBHD / "anchors.jsonl"
SUBJECT_ANCHORS = NBHD / "subject-anchors.jsonl"
IDENTITY = NBHD / "identities.json"
OWNER = "kody-w"

TWINS = {
    "ledger":  "checks whether the sentinel's claims are backed by evidence we gathered",
    "compass": "checks whether the sentinel's declared goal still matches the world",
    "pulse":   "checks whether the sentinel's work is still moving",
}


def utc_now():
    """§7 fixed-form UTC — exactly millisecond precision, Z suffix."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def identities():
    """Mint-once rappids (§6.2), minted from uuid4 — never a name-hash.

    Minted here rather than derived from the twin's name so that two
    neighborhoods with the same slugs cannot collide, and so a slug rename
    cannot silently forge a new stream of record.
    """
    if IDENTITY.exists():
        return json.loads(IDENTITY.read_text(encoding="utf-8"))
    NBHD.mkdir(parents=True, exist_ok=True)
    ids = {slug: rapp.mint_rappid(OWNER, f"twin-{slug}") for slug in TWINS}
    IDENTITY.write_text(json.dumps(ids, indent=2) + "\n", encoding="utf-8")
    return ids


def chain_path(slug):
    d = NBHD / slug
    d.mkdir(parents=True, exist_ok=True)
    return d / "chain.jsonl"


def read_chain(slug):
    p = chain_path(slug)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def emit(slug, kind, payload):
    """Append one rapp/1 frame to this twin's chain, refusing invalid frames."""
    ids = identities()
    stream_id = ids[slug]
    chain = read_chain(slug)
    head = chain[-1] if chain else None
    frame = rapp.build_frame(
        kind=kind,
        stream_id=stream_id,
        seq=(head["seq"] + 1) if head else 0,
        utc=utc_now(),
        payload=payload,
        prev=head["payload_hash"] if head else None,
        prev_wave=None,                       # §7.5 step 5: null off swarm
    )
    ok, step, why = rapp.verify_frame(frame, head=head, stream_id_of_record=stream_id)
    if not ok:
        raise ValueError(f"refusing to append an invalid frame (step {step}): {why}")
    with open(chain_path(slug), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(frame, ensure_ascii=False) + "\n")
    return frame


def verify(slug):
    """Re-verify a twin's whole chain from genesis. Returns (ok, detail)."""
    ids = identities()
    chain = read_chain(slug)
    if not chain:
        return True, "empty chain"
    head = None
    for i, frame in enumerate(chain):
        ok, step, why = rapp.verify_frame(frame, head=head, stream_id_of_record=ids[slug])
        if not ok:
            return False, f"frame {i} failed §7.5 step {step}: {why}"
        head = frame
    return True, f"{len(chain)} frames verified from genesis"


def chain_digest(frames):
    """A hash over EVERY frame_hash in order, not only the head.

    `prev` binds the predecessor's payload_hash, so rewriting an interior
    payload perturbs that frame and its successor and then stops — it never
    reaches the head. A digest over all frame_hashes has no such blind
    interior: move any frame and the digest moves.
    """
    return rapp.H("rapp/1:wave", {"hashes": [f["frame_hash"] for f in frames]})


def anchor_heads():
    """Witness our own three heads in an append-only file.

    A chain cannot detect its own truncation: when payloads repeat, `prev`
    repeats, so an interior frame can be dropped and the successors resealed
    and the result still verifies. The fix is a witness outside the chain.
    """
    ids = identities()
    rec = {"utc": utc_now(), "heads": {}}
    for slug in TWINS:
        ch = read_chain(slug)
        if ch:
            rec["heads"][slug] = {"seq": ch[-1]["seq"],
                                  "frame_hash": ch[-1]["frame_hash"],
                                  "chain_digest": chain_digest(ch),
                                  "stream_id": ids[slug]}
    ANCHORS.parent.mkdir(parents=True, exist_ok=True)
    with open(ANCHORS, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def _rewind_report(anchor_file, current_heads):
    """Compare current heads against the highest seq ever witnessed.

    Truncation shows as a head whose seq went BACKWARDS, or a seq we witnessed
    once that the chain can no longer produce. Rewriting shows as the same seq
    carrying a different frame_hash.
    """
    if not Path(anchor_file).exists():
        return {}
    highest = {}
    for line in Path(anchor_file).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        for slug, h in (rec.get("heads") or {}).items():
            prev = highest.get(slug)
            if prev is None or h.get("seq", -1) > prev.get("seq", -1):
                highest[slug] = h

    out = {}
    for slug, witnessed in highest.items():
        cur = current_heads.get(slug)
        if cur is None:
            out[slug] = {"witnessed_seq": witnessed.get("seq"), "current_seq": None,
                         "truncated": True, "rewritten": False,
                         "detail": "chain we once witnessed is gone entirely"}
            continue
        truncated = cur["seq"] < witnessed.get("seq", -1)
        rewritten = (cur["seq"] == witnessed.get("seq")
                     and cur.get("frame_hash") != witnessed.get("frame_hash"))
        out[slug] = {"witnessed_seq": witnessed.get("seq"), "current_seq": cur["seq"],
                     "truncated": truncated, "rewritten": rewritten,
                     "detail": ("head went backwards" if truncated else
                                "same seq, different frame_hash" if rewritten else "ok")}
    return out


def check_anchors():
    """Our own three chains, judged against our own witness."""
    heads = {}
    for slug in TWINS:
        ch = read_chain(slug)
        if ch:
            heads[slug] = {"seq": ch[-1]["seq"], "frame_hash": ch[-1]["frame_hash"]}
    return _rewind_report(ANCHORS, heads)


# ── the part that makes this worth running ───────────────────────────────────

def subject_heads(subject_root: Path):
    """Read the SUBJECT's chain heads, verifying each chain ourselves.

    We deliberately do not read the sentinel's own roll_call.json or
    anchors.json for this. Those are its report about itself. The whole reason
    an outside watcher exists is to produce a second opinion from the primary
    evidence — the chain files — rather than to restate the first opinion.
    """
    nb = Path(subject_root) / "neighborhood"
    ids_path = nb / "identities.json"
    ids = json.loads(ids_path.read_text(encoding="utf-8")) if ids_path.exists() else {}
    out = {}
    if not nb.is_dir():
        return out
    for d in sorted(p for p in nb.iterdir() if p.is_dir()):
        cf = d / "chain.jsonl"
        if not cf.exists():
            continue
        slug = d.name
        try:
            frames = [json.loads(l) for l in cf.read_text(encoding="utf-8").splitlines()
                      if l.strip()]
        except Exception as exc:
            out[slug] = {"readable": False, "detail": f"unparseable chain: {exc}"}
            continue
        if not frames:
            out[slug] = {"readable": True, "frames": 0, "chain_ok": True,
                         "detail": "empty chain"}
            continue

        chain_ok, detail, head = True, f"{len(frames)} frames verified from genesis", None
        for i, fr in enumerate(frames):
            ok, step, why = rapp.verify_frame(
                fr, head=head, stream_id_of_record=ids.get(slug))
            if not ok:
                chain_ok, detail = False, f"frame {i} failed §7.5 step {step}: {why}"
                break
            head = fr
        out[slug] = {"readable": True, "frames": len(frames), "chain_ok": chain_ok,
                     "detail": detail, "seq": frames[-1]["seq"],
                     "frame_hash": frames[-1]["frame_hash"],
                     "chain_digest": chain_digest(frames),
                     "utc": frames[-1].get("utc")}
    return out


def witness_subject(subject_root: Path):
    """Append the subject's heads to OUR append-only witness.

    This is the single capability the sentinel cannot have about itself. Its
    own anchor file lives inside the directory whose integrity it attests, so
    anything able to rewrite a chain is able to rewrite the witness that would
    expose it. Recording the same heads here, outside, means a later splice has
    to disagree with a file that process does not control.
    """
    heads = subject_heads(subject_root)
    rec = {"utc": utc_now(), "subject": str(subject_root),
           "heads": {s: {k: v for k, v in h.items()
                         if k in ("seq", "frame_hash", "chain_digest")}
                     for s, h in heads.items() if h.get("readable") and "seq" in h}}
    SUBJECT_ANCHORS.parent.mkdir(parents=True, exist_ok=True)
    with open(SUBJECT_ANCHORS, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def subject_rewind(subject_root: Path):
    """Has the subject's history moved under us since we first witnessed it?"""
    heads = {s: h for s, h in subject_heads(subject_root).items() if "seq" in h}
    return _rewind_report(SUBJECT_ANCHORS, heads)


def roll_call(stale_minutes=180):
    """Our own three twins: verified, and advancing."""
    now = datetime.now(timezone.utc)
    out = {}
    for slug, role in TWINS.items():
        ch = read_chain(slug)
        ok, detail = verify(slug)
        age = None
        if ch:
            try:
                age = (now - datetime.fromisoformat(
                    ch[-1]["utc"].replace("Z", "+00:00"))).total_seconds() / 60
            except Exception:
                age = None
        out[slug] = {"frames": len(ch), "chain_ok": ok, "chain_detail": detail,
                     "age_minutes": None if age is None else round(age, 1),
                     "alive": bool(ch) and age is not None and age < stale_minutes,
                     "role": role}
    return out


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "roll-call"
    if cmd == "roll-call":
        print(json.dumps(roll_call(), indent=2))
    elif cmd == "anchors":
        print(json.dumps(check_anchors(), indent=2))
    elif cmd == "subject":
        root = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.home() / "rapp-sentinel"
        print(json.dumps(subject_heads(root), indent=2))
    elif cmd == "subject-rewind":
        root = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.home() / "rapp-sentinel"
        print(json.dumps(subject_rewind(root), indent=2))
    else:
        print(__doc__)
