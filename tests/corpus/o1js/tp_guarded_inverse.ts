// @scan-as src/contracts/RatioOracle.ts
// @recall-rule O1JS_GUARDED_INVERSE
// @recall-min-severity medium
//
// V-O1J-VUL-060: Provable.if cannot guard an unconditional .div() assertion.
// Both branches evaluate in-circuit, so setRatio(_, 0) can never be proven.
import { SmartContract, method, state, State, Field, Provable } from 'o1js';

export class RatioOracle extends SmartContract {
  @state(Field) ratio = State<Field>();

  @method async setRatio(dividend: Field, divisor: Field) {
    let divisorIsZero = divisor.equals(0);
    let quotient = Provable.if(divisorIsZero, Field(0), dividend.div(divisor));
    this.ratio.set(quotient);
  }
}
