// @recall-rule O1JS_UNCONSTRAINED_WITNESS
// @recall-min-severity high
// @scan-as src/CompoundConstraint.ts
import { SmartContract, State, UInt64, PublicKey, method, state } from 'o1js';

export class CompoundConstraint extends SmartContract {
  @state(UInt64) reserve = State<UInt64>();

  @method async withdraw(to: PublicKey, a: UInt64, b: UInt64) {
    this.check(a.add(b));
    this.send({ to, amount: a });
  }

  private check(total: UInt64) {
    const current = this.reserve.getAndRequireEquals();
    total.assertLessThanOrEqual(current);
  }
}
