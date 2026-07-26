// @recall-rule NONE
// @recall-expect-absent O1JS_UNCONSTRAINED_WITNESS
// @scan-as src/Vault.test.ts
//
// Test-context suppression for the o1js backend. This contract IS vulnerable
// (`amount` is an unconstrained @method witness reaching this.send), but it
// sits at a `*.test.ts` path, where o1js projects deliberately build bad
// transactions to prove the asserts reject them. Must be silent.
import { SmartContract, UInt64, PublicKey, method } from 'o1js';

export class Vault extends SmartContract {
  @method async withdraw(to: PublicKey, amount: UInt64) {
    this.send({ to: to, amount: amount });
  }
}
