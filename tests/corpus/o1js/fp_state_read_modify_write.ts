// @scan-as src/contracts/ReadModifyWrite.ts
// @recall-rule NONE
// @recall-expect-absent O1JS_STATE_READ_AFTER_WRITE
//
// The read is nested INSIDE the write's arguments, so it observes the
// pre-write value correctly. This is the ordinary way state is updated, and
// flagging it was a real false positive: it fired on o1js's own dex and
// reducer examples.
import { SmartContract, method, state, State, Field, UInt64 } from 'o1js';

export class ReadModifyWrite extends SmartContract {
  @state(Field) counter = State<Field>();
  @state(UInt64) totalSupply = State<UInt64>();

  @method async bump(delta: UInt64) {
    this.counter.set(this.counter.getAndRequireEquals().add(1));
    this.totalSupply.set(this.totalSupply.getAndRequireEquals().sub(delta));
  }
}
