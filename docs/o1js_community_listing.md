# Contributing `o1js-scan` to the o1js community packages list

**SUBMITTED** — [o1-labs/o1js#2904](https://github.com/o1-labs/o1js/pull/2904),
opened 2026-07-30, one line added to the README's Community Packages section.

Source of the requirements:
[`CONTRIBUTING.md`](https://github.com/o1-labs/o1js/blob/main/CONTRIBUTING.md)
§ *Community packages*.

## Open item: close the duplicate PR #2898

[#2898](https://github.com/o1-labs/o1js/pull/2898) (2026-07-23) proposes the
same listing and is **still open**. It predates the npm publish and is
superseded by #2904. Two reasons beyond the duplication itself:

1. **It links only GitHub, no npm.** Every existing entry in that list is
   `[GitHub](…) and [npm](…)`, and o1js's own criterion is "published to npm;
   `npm install <your-package>` works and is all that is needed". An entry
   without an npm link reads as not meeting the bar — the package was not on
   the registry when #2898 was written.
2. **It also edits o1js's `CHANGELOG.md`**, adding "Documented the `o1js-scan`
   community package in the README." No existing community entry did that.
   Writing into a maintainer's own changelog to announce your own listing
   invites a change request on an otherwise one-line PR.

The risk is not that duplicates look untidy. It is that a maintainer triaging
the older PR first sees a non-conforming entry plus an unwanted changelog edit,
and forms a view of the submission before reaching #2904.

---

## Preconditions

The listing was npm-gated. These were the publication checks before opening the
PR:

- [x] `NPM_TOKEN` (npm **automation** token) added to repository secrets, or npm
      Trusted Publishing configured
- [x] A release cut so `publish-npm` runs and `o1js-scan` exists on the registry
- [x] `curl -s https://registry.npmjs.org/o1js-scan | head -c 40` returns package
      metadata rather than `{"error":"Not found"}`

The npm package is live at <https://www.npmjs.com/package/o1js-scan>, so the
README's Node install path is no longer ahead of the registry.

---

## Requirement-by-requirement status

| o1js requirement | Status | Note |
|---|---|---|
| "The package is published to npm. `npm install <your-package>` works and is all that is needed to use the package." | ⚠️ partial | Published at <https://www.npmjs.com/package/o1js-scan>. The wrapper additionally needs **Python 3.8+ on `PATH`** — see [The one requirement we do not meet](#the-one-requirement-we-do-not-meet). |
| "o1js must be listed as a peer dependency." | ✅ | Declared, and marked **optional** — see [On the peer dependency](#on-the-peer-dependency). |
| "Use TypeScript, and export types from `d.ts` files." | ❌ | The analyzer is Python. Ships `py.typed` for Python consumers; there is no JS API surface to type. |
| "Code must be auto-formatted with prettier." | ✅ | `.prettierrc.cjs` mirrors o1js's own options; enforced in CI (`prettier --check`). Applies to the two Node wrapper files and the wrapper smoke test — the only JS here. The analyzer is Python and is formatted by ruff. |
| "The package includes tests. If applicable, tests must demonstrate that the package's methods can successfully run as provable code." | ✅ | Full unit + corpus suite, run on Python 3.8/3.10/3.12 in CI. The provable-code clause is marked *if applicable* and is not — this is a static analyzer, it never executes inside a circuit. |
| "Public API must be documented and JSDoc comments must be present on exported methods and globals." | n/a | CLI tool; exports no JS methods or globals. Rules are documented in tables in the README. |

## The one requirement we do not meet

`npm install o1js-scan` is **not** all that is needed: the wrapper shells out to
Python 3.8+ (`python3`/`python`, or `O1JS_SCAN_PYTHON`). Say this in the PR
rather than letting a maintainer discover it.

Mitigations worth stating:

- Zero third-party dependencies on either side — no pip install step, no
  transitive npm tree.
- The wrapper fails with a clear, actionable message (`Python was not found.
  Install Python 3.8+ or set O1JS_SCAN_PYTHON.`) and exit code 2, not a stack
  trace.
- Python 3.8+ is present by default on macOS and every mainstream Linux distro,
  and on `ubuntu-latest`/`macos-latest` GitHub runners.

If maintainers consider this disqualifying, the honest answer is to accept that
and keep the tool discoverable through the Mina zkApp docs and PyPI instead.
Do not overstate this to get listed.

## On the peer dependency

`o1js` is declared as an **optional** peer dependency:

```json
"peerDependencies":     { "o1js": ">=1" },
"peerDependenciesMeta": { "o1js": { "optional": true } }
```

This satisfies the requirement as written while staying truthful. Two reasons it
must stay optional:

1. `o1js-scan` never imports `o1js`. It reads source text; it does not link
   against the library. A hard dependency would assert a relationship that does
   not exist.
2. The same binary scans **Noir** circuits (`noir-scan`), in projects with no
   `o1js` in the tree at all. Under npm ≥7 a non-optional peer dep is
   auto-installed, so a mandatory declaration would pull the entire o1js
   toolchain into every Noir-only user's `node_modules`.

Flag this in the PR — it is a deliberate deviation from the literal wording, and
a reviewer should get to weigh it rather than find it later.

## Precedent for tooling on this list

The criteria are written for provable-code libraries, but the list already
carries developer tooling:

> **zk-regex-o1js** A CLI tool for compiling ZK Regex circuits in o1js.
> [Github](https://github.com/Shigoto-dev19/zk-regex-o1js) and
> [npm](https://www.npmjs.com/package/zk-regex-o1js)

`eslint-plugin-o1js` also exists in the ecosystem on npm. Cite `zk-regex-o1js`
as precedent; do not claim the criteria were written with tooling in mind.

---

## The README diff to propose

Append to the **Community Packages** section of `README.md`, matching the
existing entry format exactly (bold name, description sentence, then
`[GitHub](...) and [npm](...)`):

```markdown
- **o1js-scan** A static analyzer for zk circuit soundness bugs in o1js zkApps and Noir circuits — flags prover-controlled witnesses that the circuit never binds. [GitHub](https://github.com/auditinfra-io/o1js-scan) and [npm](https://www.npmjs.com/package/o1js-scan)
```

Format checks against the existing four entries:

- `- **name**` bold, no backticks — matches.
- Description is a sentence fragment, no trailing period before the links on
  `o1js-elgamal`; the other three do end the sentence. Either is consistent with
  the list as it stands.
- Links spelled `[GitHub](...)` and `[npm](...)`, joined by the word `and`.
  (The list mixes `GitHub` and `Github`; use `GitHub`.)

## Submission checklist for `o1-labs/o1js`

Use this as the complete upstream PR packet.

1. Fork or clone `o1-labs/o1js`.
2. Create a branch:

   ```bash
   git checkout -b add-o1js-scan-community-package
   ```

3. Edit `README.md` and add the bullet from
   [The README diff to propose](#the-readme-diff-to-propose) under
   **Community Packages**.
4. Check the diff is README-only:

   ```bash
   git diff -- README.md
   ```

5. Commit:

   ```bash
   git add README.md
   git commit -m "Add o1js-scan to community packages"
   ```

6. Open a PR against `o1-labs/o1js:main` with:

   - **Title:** `Add o1js-scan to community packages`
   - **Body:** copy [Proposed PR body](#proposed-pr-body)

## Proposed PR body

> ### Add o1js-scan to the community packages list
>
> `o1js-scan` is a static analyzer for zk circuit soundness bugs in o1js zkApps
> and Noir circuits. It flags the class of bug that is usually not in the
> proving system but in the application's own constraints: witnesses the prover
> controls that the circuit never binds.
>
> ```console
> $ o1js-scan src/Vault.ts
> LOW      O1JS_UNCONSTRAINED_RECIPIENT   Vault.ts:23  fn=withdraw  Recipient `to` is prover-chosen in `withdraw`
> HIGH     O1JS_UNCONSTRAINED_WITNESS     Vault.ts:23  fn=withdraw  Unconstrained witness `amount` flows to send_amount in `withdraw`
> o1js-scan: 2 finding(s) [1 high, 1 low] in 1 file(s) — fails (--fail-on high)
> ```
>
> - npm: https://www.npmjs.com/package/o1js-scan
> - PyPI: https://pypi.org/project/o1js-scan/
> - Source: https://github.com/auditinfra-io/o1js-scan (Apache-2.0)
>
> **Against the community-package criteria**
>
> - Published to npm, `o1js` declared as a peer dependency, prettier-formatted
>   wrapper, a full unit + corpus test suite, documented rule tables.
> - **Two deviations I want to flag rather than paper over:**
>   1. The analyzer is written in Python, not TypeScript. The npm package is a
>      thin Node wrapper, so `npm install o1js-scan` also requires Python 3.8+
>      on `PATH`. It has no third-party dependencies on either side and fails
>      with a clear message if Python is absent.
>   2. The `o1js` peer dependency is marked **optional**. The tool never imports
>      o1js — it reads source text — and the same binary scans Noir circuits in
>      projects with no o1js present. A mandatory peer dep would be
>      auto-installed by npm ≥7 for every Noir-only user.
>
> I took `zk-regex-o1js` (a CLI tool) as precedent that the list admits
> developer tooling alongside provable-code libraries. Happy to be told the
> Python runtime requirement is disqualifying.

## Process notes

- o1js CONTRIBUTING requires an **RFC before direct code contributions**. A
  README list entry is not a code change and the guidance explicitly invites
  self-listing ("we strongly encourage you to add it to our official list"), so
  an RFC should not be needed. If a maintainer asks for one, that is their call.
- Development happens on `main`; fork and open the PR against `main`.
- No CLA or DCO is mentioned in their CONTRIBUTING.md.
