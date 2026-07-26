// @recall-rule O1JS_UNASSERTED_BOOL
// @recall-min-severity high
// @scan-as contracts/src/Mac.ts
//
// PINNED REGRESSION — confirmed true positive, disclosed.
// marekyggdrasil/mac@83cea9c contracts/src/Mac.ts (7 occurrences, this is the
// shape at :86). `commitment.equals(...)` returns a Bool and adds NO constraint
// unless asserted; the result is discarded, so the caller-preimage check the
// comment describes is never actually enforced.
//
// This fixture exists so the finding can never be silently lost to a future
// suppression heuristic. If this test fails, a change has killed a real finding.
import { SmartContract, Field, method } from 'o1js';

export class Mac extends SmartContract {
  @method async depositAsEmployer(contract_preimage: MacPreimage) {
    const commitment: Field = this.commitment.getAndRequireEquals();

    // make sure this is the right contract by checking if
    // the caller is in possession of the correct preimage
    commitment.equals(contract_preimage.getCommitment());
  }
}
