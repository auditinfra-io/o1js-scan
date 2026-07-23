# Examples

Two tiny contracts that show o1js-scan catching a real soundness bug and going
quiet once it's fixed. From the repo root:

## Vulnerable — `amount` is an unconstrained witness

```console
$ o1js-scan examples/vulnerable_vault.ts
LOW      O1JS_UNCONSTRAINED_RECIPIENT       vulnerable_vault.ts:23  fn=withdraw  Recipient `to` is prover-chosen in `withdraw`
HIGH     O1JS_UNCONSTRAINED_WITNESS         vulnerable_vault.ts:23  fn=withdraw  Unconstrained witness `amount` flows to send_amount in `withdraw`
o1js-scan: 2 finding(s) [1 high, 1 low] in 1 file(s) — fails (--fail-on high)
$ echo $?
1
```

The `HIGH` finding is the bug: `amount` is a prover-controlled `@method`
witness that reaches `this.send` with no constraint. The `LOW` recipient
finding is informational — a user naming their own withdrawal destination is
expected — and does not fail the build.

## Fixed — `amount` is bound to on-chain state

```console
$ o1js-scan examples/safe_vault.ts
LOW      O1JS_UNCONSTRAINED_RECIPIENT       safe_vault.ts:23  fn=withdraw  Recipient `to` is prover-chosen in `withdraw`
o1js-scan: 1 finding(s) [1 low] in 1 file(s) — passes (--fail-on high)
$ echo $?
0
```

`getAndRequireEquals()` adds the account precondition and
`amount.assertLessThanOrEqual(balance)` ties the amount to the recorded value,
so the high-severity finding is gone and the run passes.

## Suppressing a reviewed finding

If you've triaged a finding and want to keep CI green without loosening the
gate, annotate the line:

```ts
// o1js-scan-disable-next-line O1JS_UNCONSTRAINED_RECIPIENT
this.send({ to: to, amount: amount });
```

A bare `// o1js-scan-disable-line` (no rule id) suppresses every rule on that
line.
