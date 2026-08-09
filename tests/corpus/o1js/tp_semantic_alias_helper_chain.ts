// @recall-rule O1JS_UNCONSTRAINED_WITNESS
// @recall-min-severity high
// @scan-as src/VulnerablePayout.ts
import { SmartContract, State, UInt64, PublicKey, method, state } from 'o1js';

export class VulnerablePayout extends SmartContract {
  @state(UInt64) reserve = State<UInt64>();

  @method async withdraw(recipient: PublicKey, requested: UInt64) {
    const renamed = requested;
    const renamedAgain = renamed;
    this.forwardPayment(recipient, renamedAgain);
  }

  private forwardPayment(to: PublicKey, value: UInt64) {
    const helperAlias = value;
    this.pay(to, helperAlias);
  }

  private pay(to: PublicKey, amount: UInt64) {
    this.send({ to, amount });
  }
}
