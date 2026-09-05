// @scan-as src/contracts/UnrelatedGuard.ts
// @recall-rule NONE
// @recall-expect-absent O1JS_GUARDED_INVERSE
//
// A Provable.if whose branch divides by something the guard says nothing
// about. The division may be perfectly safe (scale is a non-zero constant),
// so firing here would be noise.
import { SmartContract, method, state, State, Field, Bool, Provable } from 'o1js';

export class UnrelatedGuard extends SmartContract {
  @state(Field) out = State<Field>();

  @method async scaled(amount: Field, enabled: Bool) {
    let scale = Field(1000);
    this.out.set(Provable.if(enabled, amount.div(scale), Field(0)));
  }
}
