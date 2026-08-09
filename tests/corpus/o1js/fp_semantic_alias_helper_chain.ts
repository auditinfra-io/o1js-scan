// @recall-rule NONE
// @recall-expect-absent O1JS_UNCONSTRAINED_WITNESS
// @scan-as src/ConstrainedPayout.ts
import { SmartContract, State, UInt64, PublicKey, method, state } from 'o1js';

export class ConstrainedPayout extends SmartContract {
  @state(UInt64) reserve = State<UInt64>();

  @method async withdraw(recipient: PublicKey, requested: UInt64) {
    const renamed = requested;
    this.checkAgainstReserve(renamed);
    this.forwardPayment(recipient, renamed);
  }

  private checkAgainstReserve(value: UInt64) {
    const current = this.reserve.getAndRequireEquals();
    const checkAlias = value;
    checkAlias.assertLessThanOrEqual(current);
  }

  private forwardPayment(to: PublicKey, value: UInt64) {
    const helperAlias = value;
    this.pay(to, helperAlias);
  }

  private pay(to: PublicKey, amount: UInt64) {
    this.send({ to, amount });
  }
}
