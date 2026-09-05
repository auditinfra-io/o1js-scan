// @scan-as src/contracts/RepeatedRead.ts
// @recall-rule NONE
// @recall-expect-absent O1JS_PRECONDITION_OVERWRITTEN
//
// Reading the same state twice is idiomatic and must stay quiet:
// getAndRequireEquals() is a different method, and two identical
// requireEquals() calls set the same precondition to the same value, which
// cannot lose a constraint.
import { SmartContract, method, state, State, Field } from 'o1js';

export class RepeatedRead extends SmartContract {
  @state(Field) total = State<Field>();

  @method async bump(delta: Field) {
    let a = this.total.getAndRequireEquals();
    let b = this.total.getAndRequireEquals();
    a.assertEquals(b);

    let onChain = this.total.get();
    this.total.requireEquals(onChain);
    this.total.requireEquals(onChain);

    this.total.set(a.add(delta));
  }
}
