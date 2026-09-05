// Reproducer for V-O1J-VUL-060 (Veridise, Info, "Acknowledged")
//   "Inverse assertion allows for common anti-pattern"
//
// Field.div() / inv() / sqrt() assert unconditionally that the inverse or root
// exists. Both branches of Provable.if are evaluated in-circuit, so guarding a
// division with Provable.if does NOT avoid the assertion: the circuit becomes
// unsatisfiable for exactly the input the guard was written to handle.
//
// Veridise's impact line: "Users may deploy contracts which always error when
// certain values are 0."
import { SmartContract, method, state, State, Field, Provable } from 'o1js';

export class RatioOracle extends SmartContract {
  @state(Field) ratio = State<Field>();

  @method async setRatio(dividend: Field, divisor: Field) {
    let divisorIsZero = divisor.equals(0);

    // Intent: fall back to 0 when the divisor is zero.
    // Reality: dividend.div(divisor) asserts divisor !== 0 regardless of the
    // branch, so setRatio(_, 0) can never be proven.
    let quotient = Provable.if(divisorIsZero, Field(0), dividend.div(divisor));

    this.ratio.set(quotient);
  }
}
