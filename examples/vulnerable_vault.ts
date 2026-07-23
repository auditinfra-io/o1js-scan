import {
  SmartContract,
  UInt64,
  PublicKey,
  State,
  state,
  method,
} from 'o1js';

// A minimal, DELIBERATELY VULNERABLE zkApp used to demonstrate o1js-scan.
// Run:  o1js-scan examples/vulnerable_vault.ts
export class VulnerableVault extends SmartContract {
  @state(UInt64) balance = State<UInt64>();

  // BUG: `amount` is a prover-controlled `@method` witness that flows straight
  // into a value transfer without ever being constrained. A prover can pass any
  // value and drain the account — the o1js analog of an under-constrained
  // Circom signal.  ->  O1JS_UNCONSTRAINED_WITNESS (high)
  //
  // `to` is also prover-chosen, but that is normal for a user-initiated
  // withdrawal.  ->  O1JS_UNCONSTRAINED_RECIPIENT (low, informational)
  @method async withdraw(to: PublicKey, amount: UInt64) {
    this.send({ to: to, amount: amount });
  }
}
