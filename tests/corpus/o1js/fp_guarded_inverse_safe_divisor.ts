// @scan-as src/contracts/SafeDivide.ts
// @recall-rule NONE
// @recall-expect-absent O1JS_GUARDED_INVERSE
//
// The correct fix for V-O1J-VUL-060, and it must stay quiet: the divisor is
// made safe FIRST, so the division never asserts against zero, and the result
// is selected afterwards. This is the shape the rule's own advice recommends.
import { SmartContract, method, state, State, Field, Provable } from 'o1js';

export class SafeDivide extends SmartContract {
  @state(Field) ratio = State<Field>();

  @method async setRatio(dividend: Field, divisor: Field) {
    let isZero = divisor.equals(0);
    let safeDivisor = Provable.if(isZero, Field(1), divisor);
    let quotient = Provable.if(isZero, Field(0), dividend.div(safeDivisor));
    this.ratio.set(quotient);
  }
}
