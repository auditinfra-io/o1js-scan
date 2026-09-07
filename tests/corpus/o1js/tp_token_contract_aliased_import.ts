// @scan-as src/dex/token.ts
// @recall-rule O1JS_UNCONSTRAINED_WITNESS
// @recall-min-severity medium
//
// o1js's own dex example aliases the base class so it can reuse the name:
//
//     import { TokenContract as BaseTokenContract } from 'o1js';
//     class TokenContract extends BaseTokenContract { ... }
//
// A fixed list of base-class names misses that, including in the repository
// scripts/o1js_upstream_canary.sh scans. The gate resolves aliases of a known
// base from the o1js import instead.
import {
  TokenContract as BaseTokenContract,
  method,
  state,
  State,
  UInt64,
  AccountUpdateForest,
} from 'o1js';

export class TokenContract extends BaseTokenContract {
  @state(UInt64) total = State<UInt64>();

  async approveBase(forest: AccountUpdateForest) {
    forest.isEmpty().assertFalse();
  }

  @method async setTotal(amount: UInt64) {
    this.total.set(amount);
  }
}
