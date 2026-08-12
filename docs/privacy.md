# Private code and public contributions

`o1js-scan` runs locally: the CLI reads the path you provide and writes to the
terminal or a requested SARIF file. It has no telemetry or automatic upload.

Your surrounding tools still matter. CI services may retain logs and artifacts,
and the GitHub Action uploads SARIF to GitHub code scanning. Scanner output can
include paths, identifiers, source fragments, and line numbers, so give it the
same access controls as the repository it describes.

## Sharing a reproducer

You can usually report a false positive or missed constraint without sharing
the application that revealed it:

1. Write a new, minimal example with invented contract and variable names.
2. Keep only the syntax and constraint relationship needed for the behavior.
3. Remove real addresses, keys, constants, comments, and domain logic.
4. Run the same scanner version on the new file and confirm the behavior.
5. Review the snippet and scanner output before posting them publicly.

If the pattern cannot be separated from private work, it is fine to provide
only the language, scanner version, and rule id—or not report it publicly.

## Improving the open scanner without private material

Useful public work includes compatibility tests based on public o1js APIs,
synthetic vulnerable/fixed examples, false-positive guards, clearer diagnostics,
SARIF and CI improvements, performance work, packaging, and documentation.
These make the tool more capable and trustworthy without disclosing client code
or proprietary detection research.
