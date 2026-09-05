// @scan-as src/contracts/Counter.ts
// @recall-rule O1JS_STATE_READ_AFTER_WRITE
// @recall-min-severity medium
//
// V-O1J-VUL-030: set() records the change on the AccountUpdate but does not
// write through to get(). `current` is the pre-increment value, so `total`
// receives n, not n + 1.
import { SmartContract, method, state, State, Field } from 'o1js';

export class Counter extends SmartContract {
  @state(Field) counter = State<Field>();
  @state(Field) total = State<Field>();

  @method async increment() {
    let n = this.counter.getAndRequireEquals();
    this.counter.set(n.add(1));
    let current = this.counter.getAndRequireEquals();
    this.total.set(current);
  }
}
