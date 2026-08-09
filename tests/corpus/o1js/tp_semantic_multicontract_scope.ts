// @recall-rule O1JS_UNCONSTRAINED_WITNESS
// @recall-min-severity high
// @scan-as src/MultipleContracts.ts
import { SmartContract, State, UInt64, PublicKey, method, state } from 'o1js';

export class Vulnerable extends SmartContract {
  @method async withdraw(to: PublicKey, amount: UInt64) {
    this.send({ to, amount });
  }
}

export class Safe extends SmartContract {
  @state(UInt64) reserve = State<UInt64>();

  @method async withdraw(to: PublicKey, amount: UInt64) {
    const current = this.reserve.getAndRequireEquals();
    amount.assertLessThanOrEqual(current);
    this.send({ to, amount });
  }
}
