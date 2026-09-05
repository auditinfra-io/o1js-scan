// @scan-as src/contracts/Branchy.ts
// @recall-rule NONE
// @recall-expect-absent O1JS_PRECONDITION_OVERWRITTEN
//
// Mutually exclusive JS branches are not an overwrite: the `if` is evaluated at
// circuit-build time, so exactly one of these preconditions is ever emitted.
// Flagging this shape was a real false positive during development.
import { SmartContract, method, UInt32 } from 'o1js';
export class Branchy extends SmartContract {
  @method async settle(isAdmin: boolean) {
    if (isAdmin) {
      this.account.nonce.requireEquals(UInt32.from(1));
    } else {
      this.account.nonce.requireEquals(UInt32.from(2));
    }
  }
}
