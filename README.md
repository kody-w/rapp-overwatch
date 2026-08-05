# rapp-overwatch

**Three twins that watch a watchdog, from outside the directory it can write to.**

The subject is [`kody-w/rapp-sentinel`](https://github.com/kody-w/rapp-sentinel), which keeps two GitHub-native platforms alive overnight. It is good at its job. That is exactly why it needs this.

---

## Why watch a watchdog

A watchdog is the one component whose failure is silent by construction. When it stops noticing, the symptom is that everything looks fine.

The sentinel's own history already contains that shape twice:

- a liveness probe attested **`alive` fourteen times without ever touching the endpoint** it existed to check — a `GET /` returning 200 from a brainstem that could no longer answer a single turn
- a guardian **exited 0 for five days while unauthenticated**

Both reported green the whole time. The sentinel now checks both of those specific things about itself, which is precisely the reason the next such gap will be somewhere it is not looking. You cannot close this class of hole from inside; a component's blind spot is defined by what it thinks to check.

There is a second, duller failure that had already happened when this was built. The sentinel's `direction.json` names **two** repositories. The ecosystem it operates in now has **more than twenty** actively pushed, several load-bearing for the two it watches. Nobody decided to narrow the scope. The scope stayed still and the world moved. The first tick of this watcher reported it:

```
c_coverage: watches 2/11 expected; uncovered: openrappter, public-art-collective,
rapp-1, rapp-egg-hub, rapp-local-install, rapp-map, rapp-moment, rapp-sentinel,
rapp-spine
```

Note the ninth entry. The sentinel does not watch itself.

## Three twins, three vantages

They are separate because the failure modes are genuinely unrelated, and one check that mixes them reports a single verdict for three different reasons. Each twin keeps its **own** `rapp/1` hash chain and emits a frame carrying only its own findings, so a wrong twin cannot launder a verdict through the other two.

| twin | asks | catches |
|---|---|---|
| **ledger** | are its claims backed by evidence *we* gathered? | forged, truncated or rewritten history; a stale verdict served as current |
| **compass** | does its declared goal still match the world? | scope that narrowed without a decision; a deleted boundary; two config files disagreeing |
| **pulse** | is work still moving? | a stopped loop; permanent green; a check that silently stopped being registered |

## The one thing the subject cannot do for itself

The sentinel anchors its chain heads to an append-only witness — good practice, and it caught real truncation. But **that witness lives inside the directory whose integrity it attests.** Anything able to rewrite a chain is able to rewrite the file that would expose it.

This watcher records the same heads in `neighborhood/subject-anchors.jsonl`, in a different directory, from a different process, under a different launchd job. A later splice now has to disagree with something that process does not control.

That is the whole argument for independence, and it is why this shares nothing with the sentinel but the `rapp/1` frame format (vendored, authority [`kody-w/rapp-1`](https://github.com/kody-w/rapp-1)). Delete `~/rapp-sentinel` entirely and every frame here still verifies.

## Every guard has been seen firing

```
$ python3 prove.py
  [FIRES] l_chains_verify      when: an interior frame payload is rewritten
          said: brainstem: frame 54 failed §7.5 step 2: payload_hash mismatch
  [FIRES] l_no_rewind          when: five frames are dropped after we witnessed them
          said: brainstem: head went backwards (witnessed 107, now 102)
  [FIRES] l_selfreport_agrees  when: subject is truncated but reports truncated=false
          said: brainstem: subject says truncated=False, we measured True
  ...
  14/14 guards proven to fire and then go quiet
```

Each scenario slips a **throwaway copy** of the subject and asserts the matching check fails, then asserts the same check passes on a clean copy. Both halves matter: a check that fails on everything is as useless as one that fails on nothing, and only the pair tells them apart.

`c_coverage` owns two scenarios, and the second is the important one. Its first
version compared a declared list against an expected list — which made it
satisfiable by **editing a list**. `cares_about` is read by no code at all and
`watch_repos` only by the dashboard, so appending a name widens the declaration
and watches nothing. The guard now also requires every declared repository to be
referenced by an actual check, and the scenario proves the cheat is refused:

```
[FIRES] c_coverage
        when: scope is widened by declaration only, no check
        said: declared but never referenced by any check: not-actually-watched
```

A guard that a declaration can satisfy is a guard the declaration owns.

`p_self_checks_complete` closes the matching hole in *this* repository. `BY_TWIN`
is a dict literal, so deleting a name removed a check and the tick simply
reported one fewer entry — the exact defect this repo diagnosed in
rapp-sentinel and then kept. `required_checks.json` names the expected set.

`prove.py` alone could not have caught it: the harness calls `checks.<name>()`
directly, so a check deleted from the registry keeps a passing scenario while
the tick stops running it. Proving a guard **fires** is not the same as proving
it **runs**, and only the manifest checks the second.

This is not ceremony. `c_coverage` initially reported `BROKEN` here — not because the check was wrong, but because it already fails against the real sentinel, so "clean" was not clean and the scenario proved nothing. A guard nobody has watched fail is indistinguishable from a guard that cannot fail, which is the entire reason this repository exists.

`prove.py` never writes to `~/rapp-sentinel`. Neither does anything else here.

## Run it

```bash
python3 overwatch.py verdict   # run the checks, print, change nothing
python3 overwatch.py tick      # + emit three frames and anchor
python3 overwatch.py report    # the paragraph a person needs at 3am
python3 prove.py               # make all twelve guards fire

python3 twins.py roll-call        # our three chains
python3 twins.py subject-rewind   # has the subject's history moved under us?

bash install-launchd.sh        # every 30 minutes, via launchd
```

Ticks are cheap and invoke **no model**: they read files, verify hashes, append. Deciding what a finding *means* is left to whoever reads the report, because a watcher that reasons on every tick has a budget, and a budget is a reason to skip a tick.

The interval is deliberately **slower** than the sentinel's 15 minutes. Sampling a watchdog faster than it ticks produces observations that say nothing new, and the green-streak counter then measures our own cadence instead of its behaviour.

## Boundaries

From `direction.json`, and enforced by the design rather than by intention:

- Never write to the subject's directory. **Read-only, always** — a watcher that can edit its subject can edit the evidence.
- Never restart, repair or reconfigure the subject. Report; do not intervene.
- Never trust its report about itself where primary evidence exists. Chains are verified from genesis here, not restated from its `roll_call.json`.
- Never claim it is healthy from a check that cannot fail.
- Never rewrite published history, including our own.

There is no repair arm and no escalation path on purpose. The sentinel has one, with a budget and a cooldown. Two autonomous things repairing the same estate is how you get a fix and its revert racing at 3am.

MIT © RAPP ecosystem — see the [map](https://github.com/kody-w/rapp-map).
