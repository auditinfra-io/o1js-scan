// @scan-as src/contracts/VestingClaim.ts
// @recall-rule O1JS_PRECONDITION_OVERWRITTEN
// @recall-min-severity medium
//
// V-O1J-VUL-012: preconditions are set, not accumulated. The vesting window
// guard is silently replaced by the wider sanity bound added after it.
import { SmartContract, method, state, State, UInt64, UInt32 } from 'o1js';

export class VestingClaim extends SmartContract {
  @state(UInt64) claimed = State<UInt64>();

  @method async claim(amount: UInt64) {
    this.network.timestamp.requireBetween(UInt64.from(1000), UInt64.from(2000));
    this.network.timestamp.requireBetween(UInt64.from(0), UInt64.from(5000));

    let alreadyClaimed = this.claimed.getAndRequireEquals();
    this.claimed.set(alreadyClaimed.add(amount));
  }
}
