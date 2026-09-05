// Reproducer for V-O1J-VUL-030 (Veridise, Warning, "Acknowledged")
//   "Prover errors when calling set() on same contract"
//
// set() records an app-state change on the AccountUpdate; it does not write
// through to what get() reads. A get() after a set() in the same method still
// observes the OLD value, and variable caching extends this across method
// calls on the same contract within one transaction.
//
// The author believes `total` receives the incremented counter. It receives
// the pre-increment value.
import { SmartContract, method, state, State, Field } from 'o1js';

export class Counter extends SmartContract {
  @state(Field) counter = State<Field>();
  @state(Field) total = State<Field>();

  @method async increment() {
    let n = this.counter.getAndRequireEquals();
    this.counter.set(n.add(1));

    // Reads the pre-set value: this is `n`, not `n + 1`.
    let current = this.counter.getAndRequireEquals();
    this.total.set(current);
  }
}
