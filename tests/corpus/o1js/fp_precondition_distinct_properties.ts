// @scan-as src/contracts/DistinctPreconditions.ts
// @recall-rule NONE
// @recall-expect-absent O1JS_PRECONDITION_OVERWRITTEN
//
// One precondition each on several distinct properties. Nothing is overwritten
// and this is exactly how a careful contract pins its execution context.
import { SmartContract, method, state, State, UInt64, UInt32 } from 'o1js';

export class DistinctPreconditions extends SmartContract {
  @state(UInt64) cap = State<UInt64>();

  @method async settle(limit: UInt64) {
    this.network.timestamp.requireBetween(UInt64.from(1000), UInt64.from(2000));
    this.network.blockchainLength.requireBetween(UInt32.from(10), UInt32.from(20));
    this.account.nonce.requireEquals(UInt32.from(3));
    this.cap.requireEquals(limit);
  }
}
