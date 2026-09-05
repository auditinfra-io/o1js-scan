// @scan-as src/contracts/InlineGuard.ts
// @recall-rule O1JS_GUARDED_INVERSE
// @recall-min-severity medium
//
// Same defect with the guard written inline rather than via a local.
import { SmartContract, method, state, State, Field, Provable } from 'o1js';

export class InlineGuard extends SmartContract {
  @state(Field) out = State<Field>();

  @method async invert(x: Field) {
    this.out.set(Provable.if(x.equals(0), Field(0), x.inv()));
  }
}
