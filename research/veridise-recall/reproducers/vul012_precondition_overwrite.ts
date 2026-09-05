// Reproducer for V-O1J-VUL-012 (Veridise, Medium, "Partially Fixed")
//   "Asserting preconditions may overwrite previous assertions"
//
// Preconditions are SET, not accumulated. A second requireBetween/requireEquals
// on the same property silently discards the first. In-circuit assertions
// compose; preconditions do not, and nothing warns you.
//
// Here the author believes the claim window is the intersection [1000, 2000),
// but only the second call survives, so the real window is [0, 5000).
import { SmartContract, method, state, State, UInt64, UInt32 } from 'o1js';

export class VestingClaim extends SmartContract {
  @state(UInt64) claimed = State<UInt64>();

  @method async claim(amount: UInt64) {
    // Guard 1: the vesting window.
    this.network.timestamp.requireBetween(UInt64.from(1000), UInt64.from(2000));

    // Guard 2: added later, meant as a sanity bound on top of guard 1.
    // This OVERWRITES guard 1. The vesting window is no longer enforced.
    this.network.timestamp.requireBetween(UInt64.from(0), UInt64.from(5000));

    let alreadyClaimed = this.claimed.getAndRequireEquals();
    this.claimed.set(alreadyClaimed.add(amount));
    this.send({ to: this.sender.getAndRequireSignature(), amount });
  }

  @method async withdrawAt(height: UInt32) {
    // Same shape with requireEquals: a.requireEquals(b) then a.requireEquals(c)
    // implies a === c, NOT a === b && a === c.
    this.network.blockchainLength.requireEquals(height);
    this.network.blockchainLength.requireEquals(UInt32.from(0));
  }
}
