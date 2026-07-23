# Security Policy

## What this project is

`o1js-scan` is a static analyzer. The findings it reports describe potential
soundness issues in **the o1js zkApp source code you point it at** — they are
not vulnerabilities in `o1js-scan` itself. Treat findings as a starting point
for human review, not proofs (see "Known limitations" in the README).

## Reporting a vulnerability *in o1js-scan*

If you find a security-relevant defect in the scanner itself — for example a
crafted input file that hangs or crashes it (a denial-of-service on a CI run),
or a way to make it silently miss or misreport findings in a way an attacker
could rely on — please report it privately:

1. Preferred: open a private report via GitHub's **Security → "Report a
   vulnerability"** on this repository (GitHub private vulnerability reporting).
2. If that is unavailable, open a regular
   [issue](https://github.com/auditinfra-io/o1js-scan/issues) describing the
   impact **without** a working exploit payload, and note that you have a
   proof-of-concept to share privately.

Please include the o1js-scan version (`o1js-scan --version`), your Python
version, and a minimal reproducer. We aim to acknowledge reports within a few
business days. This is a best-effort community project, not a funded program —
there is no bug bounty.

## Reporting a false negative / false positive

A missed or spurious finding that is **not** exploitable against the scanner
itself is a correctness bug, not a security issue — please use the
[false-positive issue template](https://github.com/auditinfra-io/o1js-scan/issues/new/choose)
so it can be triaged in the open.

## Supported versions

Fixes land on the latest released minor version. Older versions are not
back-patched; upgrade to pick up security fixes.
