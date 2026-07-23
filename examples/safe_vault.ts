import {
  SmartContract,
  UInt64,
  PublicKey,
  State,
  state,
  method,
} from 'o1js';

// The fixed counterpart to vulnerable_vault.ts.
// Run:  o1js-scan examples/safe_vault.ts   ->  no high/critical findings
export class SafeVault extends SmartContract {
  @state(UInt64) balance = State<UInt64>();

  // FIX: bind `amount` to on-chain state before sending. Reading the balance
  // with `getAndRequireEquals()` adds the account precondition, and the
  // ordering assertion ties `amount` to that recorded value, so a prover can
  // no longer choose an arbitrary amount. The recipient stays caller-chosen by
  // design (reported only as the low, informational recipient rule).
  @method async withdraw(to: PublicKey, amount: UInt64) {
    const balance = this.balance.getAndRequireEquals();
    amount.assertLessThanOrEqual(balance);
    this.send({ to: to, amount: amount });
    this.balance.set(balance.sub(amount));
  }
}
