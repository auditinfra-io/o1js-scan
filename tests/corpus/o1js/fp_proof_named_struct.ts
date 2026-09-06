// @scan-as src/contracts/BridgeContract.ts
// @recall-rule NONE
// @recall-expect-absent O1JS_UNVERIFIED_PROOF
//
// Found by the held-out benchmark in zk0ath/usdm@1014184b, where this shape
// produced SIXTY false HIGH findings in one file: `BlockProof` is a user
// Struct, not an o1js Proof, and its `verify()` result is folded into an
// assertion. The `*Proof` naming convention alone is not evidence of a
// recursive proof.
import { SmartContract, method, Struct, Field, Bool } from 'o1js';

export class BlockProof extends Struct({
  signer: Field,
  signature: Field,
}) {
  verify(root: Field, block: Field): Bool {
    return this.signer.equals(root).and(this.signature.equals(block));
  }
  isEmpty(): Bool {
    return this.signer.equals(Field(0));
  }
}

export class BridgeContract extends SmartContract {
  @method update(newBlock: Field, proof1: BlockProof, proof2: BlockProof) {
    let allValid = Bool(true);
    for (const proof of [proof1, proof2]) {
      allValid = allValid.and(proof.isEmpty().or(proof.verify(newBlock, newBlock)));
    }
    allValid.assertEquals(Bool(true));
  }
}
