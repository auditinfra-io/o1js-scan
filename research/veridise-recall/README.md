# Measuring o1js-scan against published audit findings

*What an independent ZK audit firm found in o1js, how much of it an
application-level scanner could ever see, and how much this one currently sees.*

---

## Why this exists

`docs/mina_calibration.md` measures true and false positives on live zkApp
repositories. That is the tool grading its own homework: the findings it counts
are the findings it produced. An honest recall number needs ground truth
somebody else established.

Two candidate corpora were examined. One worked.

## Corpus 1 — Auro Wallet audits: a null result

`github.com/aurowallet/audit-reports` carries three third-party audits:

| Audit | Findings |
|---|---:|
| Least Authority, extension, 2021 | 4 issues + 7 suggestions |
| OtterSec, extension, 2024 | 3 vulnerabilities + 5 general |
| OtterSec, mobile app, 2024 | 2 vulnerabilities + 3 general |
| **Total** | **24** |

**Zero are circuit or constraint findings.** They are origin spoofing, PBKDF2
iteration counts, GraphQL injection and batching DoS, path traversal, a local
bridge service leaking private keys, SSL pinning, sensitive data left in memory
after lock.

`o1js-scan` scores 0/24, and the number means nothing. These audit *a wallet*,
and a wallet has no circuits. Reporting "0/24 recall" from this corpus, or
concluding anything about Mina audit coverage from it, would be selection bias:
the sample was chosen by which reports happened to be public, not by whether
they could contain the bug class in question.

Recorded here so the negative result is not silently discarded.

## Corpus 2 — the Veridise o1js audit

o1js ships its own audit at `audits/VAR_o1js_240318_o1js_V3.pdf` (Veridise, V3,
2024-08-27, 199 pages). **63 findings against o1js itself**, at the circuit and
proof-system layer.

| Severity | Count |  | Type | Count |
|---|---:|---|---|---:|
| Critical | 2 |  | Logic Error | 18 |
| High | 7 |  | Maintainability | 13 |
| Medium | 8 |  | Data Validation | 10 |
| Low | 11 |  | **Under-constrained Circuit** | **9** |
| Warning | 22 |  | Hash Collision | 4 |
| Info | 13 |  | Over-constrained Circuit | 3 |
|  |  |  | Other (DoS, race, authz, tx-order, usability) | 6 |

Every finding carries a machine-readable `Type` field, so this table is
extracted, not hand-assigned.

### The scope question, stated before measuring

`o1js-scan` analyzes **application** source: `@method` bodies in zkApps. The
Veridise findings are bugs in **o1js itself**. Most of them are invisible to any
analyzer of application code, and that is not a deficiency — a developer writing
entirely correct code still hits a missing range check in `assertOnCurve`. There
is no pattern in their source to find.

So the answerable question is not "what is the recall?" but:

> Of 63 findings in o1js, how many describe a defect a developer can commit in
> their own zkApp — and of those, how many does o1js-scan catch?

Classification rule, applied in `classification.json`:

* **app-expressible** — a developer can commit the same defect in their own source
* **library-internal** — correct application code still hits it

| Class | Count |
|---|---:|
| Library-internal | 58 |
| Borderline | 2 |
| **App-expressible** | **3** |

## Result: 1 of 3

| Finding | Sev | Anti-pattern | Detected |
|---|---|---|---|
| `V-O1J-VUL-012` | Medium | two preconditions on one property; the second silently discards the first | **no** |
| `V-O1J-VUL-030` | Warning | state `get()` after `set()` reads the pre-set value | **no** |
| `V-O1J-VUL-060` | Info | `div()`/`inv()`/`sqrt()` inside a `Provable.if` branch asserts unconditionally | **yes**, since `O1JS_GUARDED_INVERSE` |

Reproducers are in `reproducers/`, as minimal zkApps a developer could plausibly
write. Reproduce with:

```bash
python3 -m o1js_scan.cli research/veridise-recall/reproducers --lang o1js --fail-on none
# MEDIUM  O1JS_GUARDED_INVERSE  vul060_div_in_provable_if.ts:22  fn=setRatio
```

The other two reproducers stay silent, which is the point of keeping them here:
they are the measured gap, and this file is where the number gets updated when
that changes.

## What this says

Three of Veridise's findings are not really library bugs at all — they are
**API-shaped traps**. The library behaves as documented; the documentation is
just not what a reasonable developer assumes:

* preconditions **set** rather than **accumulate**, so guards silently replace
  each other where in-circuit assertions would compose;
* `set()` does not write through to `get()`, so a read-after-write in one method
  returns stale state;
* both branches of `Provable.if` are evaluated in-circuit, so guarding a
  division does not prevent its unconditional assertion.

Each is a static pattern in application source. Each is currently undetected.
That makes them rule candidates with an unusually strong provenance: an
independent audit firm already judged them worth reporting, so a rule is not
speculation about what developers get wrong.

`O1JS_GUARDED_INVERSE` is **implemented** as of 0.17.0 — the first rule in this
project derived from an independent audit finding rather than from a pattern
seen in the wild. It fires on both reproducer shapes (guard via a named local,
and guard written inline), stays quiet on the corrected form that makes the
divisor safe before dividing, and stays quiet when the guard says nothing about
the divisor. Across the fourteen-repo Mina corpus and both pinned o1js releases
it produces **zero** findings, so it introduced no false positives and left
every pinned snapshot unchanged.

`O1JS_PRECONDITION_OVERWRITTEN` and `O1JS_STATE_READ_AFTER_WRITE` remain
proposed in `classification.json`.

## Limits of this study

* **One report, one library.** 63 findings from one audit of one codebase. It
  says nothing about recall on zkApp audits, because no comparable public corpus
  of audited zkApps exists.
* **The 58/3 split is a judgement call.** It is written down per finding in
  `classification.json` so it can be argued with, and the boundary cases are
  listed rather than buried.
* **The audit predates the current code.** V1 was June 2024 against commit
  `8dde2c3`; most findings are fixed. The question asked here is whether the
  scanner *would have* caught them, not whether they are still live.
* **1/3 is a small denominator.** It supports "here are three concrete gaps,
  one now closed". It does not support any claim about detection rate.
* **Zero real-world hits cuts both ways.** No false positives is the good
  reading; the other is that this anti-pattern may simply be rare in the public
  corpus, so the rule's value is unproven until it fires on real code.
