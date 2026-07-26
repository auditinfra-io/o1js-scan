// @recall-rule O1JS_UNCONSTRAINED_WITNESS
// @recall-min-severity high
// @scan-as src/Vault.ts
//
// MUTATION of fp_o1js_test_path.ts: the contract bytes are IDENTICAL; only the
// path changes, from `src/Vault.test.ts` to `src/Vault.ts`. In production that
// unconstrained witness is a drainable bug, so the rule must fire. This is what
// bounds the suppression: it silences test paths, not production code.
import { SmartContract, UInt64, PublicKey, method } from 'o1js';

export class Vault extends SmartContract {
  @method async withdraw(to: PublicKey, amount: UInt64) {
    this.send({ to: to, amount: amount });
  }
}
