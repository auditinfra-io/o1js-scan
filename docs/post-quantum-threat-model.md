# Post-quantum review guide

O(1) Labs' [*Qubit or Not Qubit*](https://www.o1labs.org/blog/qubit-or-not-qubit)
is a useful prompt to separate two questions that are easy to conflate:

1. Is an application circuit constrained correctly today?
2. Will every cryptographic assumption used by the application and its proof
   system remain secure against a sufficiently capable quantum computer?

`o1js-scan` helps with the first question. It does **not** answer the second.
That boundary matters: adding a rule that searches for names such as `Signature`,
`Poseidon`, or `PublicKey` would report syntax, not the security assumptions or
deployment lifetime that determine post-quantum risk.

## What carries over to an o1js review

The article's practical lesson is to inventory assumptions rather than label an
entire system “quantum safe” or “quantum unsafe.” For an o1js application, keep
a review table like this alongside the normal constraint audit:

| Layer | Questions for the review |
| --- | --- |
| User authorization | Which signature scheme authorizes an account update? Can the authorization key or scheme be migrated before it is unsafe? |
| In-circuit cryptography | Does custom verification depend on an elliptic-curve discrete-log assumption, a hash, or another primitive? What security level is claimed against classical and quantum attacks? |
| Commitments and stored state | How long must a commitment remain hiding or binding? Can stored commitments be versioned and re-created under a replacement scheme? |
| Proof system and chain | Which assumptions belong to o1js/Kimchi and Mina rather than application code? What upgrade or migration mechanism is available at that layer? |
| Off-chain dependencies | Do relayers, bridges, oracles, key stores, and encrypted backups add longer-lived confidentiality or authentication requirements? |

Do not treat all primitives alike. Large fault-tolerant quantum computers would
affect public-key constructions based on discrete logarithms differently from
hash-based constructions. Quantum search also changes the effective security
margin of hashes without making every hash use automatically insecure. Parameter
sizes, the exact construction, the desired security level, and how long the
protected value must remain secure all belong in the decision.

## Recommended workflow

1. **Run `o1js-scan` for application soundness.** Resolve unconstrained inputs,
   missing state preconditions, unasserted circuit booleans, and unsafe
   permissions independently of the primitive inventory.
2. **Create a cryptographic bill of materials.** Record every signature, hash,
   commitment, proof, encryption scheme, curve, and trusted external service;
   include the library and protocol versions instead of inferring algorithms
   from source-level names.
3. **Assign a lifetime and consequence.** Authentication generally needs to
   survive until an authorization can no longer be replayed or forged, while
   private data may need protection long after the transaction is finalized.
4. **Separate application and platform controls.** Application developers can
   version state, rotate keys, and design migration paths. They cannot replace
   the chain's proof system from inside an `@method`; track Mina and o1js upgrade
   guidance for those assumptions.
5. **Test crypto agility before it is urgent.** Specify version tags and reject
   ambiguous encodings, preserve a governed migration path, and rehearse moving
   keys and persistent commitments. An upgrade switch that has never been tested
   is not a mitigation.
6. **Revisit the inventory.** Quantum capability estimates and ecosystem
   migrations change. Review against current O(1) Labs, Mina, o1js, and relevant
   standards guidance rather than freezing a conclusion from this document.

## Why this is documentation, not a scanner rule

Post-quantum suitability is a property of a concrete construction, parameters,
deployment, and time horizon. This repository intentionally performs shallow
source analysis and does not resolve package versions, calculate primitive
security levels, inspect chain configuration, or predict migration timelines.
A lexical warning would therefore create false assurance when absent and noise
when present.

SARIF from `o1js-scan` should be one input to the review, not the cryptographic
inventory itself. A clean scan says nothing about the post-quantum security of
the application, Kimchi, Mina consensus, account signatures, or off-chain
systems.

## Deeper analysis

The separate full scanner maintained in the
[`audit-engine-cli` repository](https://github.com/auditinfra-io/audit-engine-cli)
can perform deeper analysis than this lightweight lexical scanner. This guide
does not enumerate its proprietary checks, detection strategies, or
implementation details. That separation lets `o1js-scan` state its limits and
provide a useful public review checklist without disclosing the knowledge used
by the full scanner.
