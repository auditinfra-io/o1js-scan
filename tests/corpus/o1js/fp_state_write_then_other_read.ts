// @scan-as src/contracts/DistinctFields.ts
// @recall-rule NONE
// @recall-expect-absent O1JS_STATE_READ_AFTER_WRITE
//
// Writing one field and reading a different one is not a read-after-write.
import { SmartContract, method, state, State, Field } from 'o1js';

export class DistinctFields extends SmartContract {
  @state(Field) a = State<Field>();
  @state(Field) b = State<Field>();

  @method async shuffle(x: Field) {
    this.a.set(x);
    let previousB = this.b.getAndRequireEquals();
    this.b.set(previousB.add(x));
  }
}
