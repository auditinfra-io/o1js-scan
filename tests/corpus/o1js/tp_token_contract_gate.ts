// @scan-as src/FungibleToken.ts
// @recall-rule O1JS_UNCONSTRAINED_WITNESS
// @recall-min-severity medium
//
// The contract gate matched `extends SmartContract` alone until 0.20.0, so
// every `extends TokenContract` zkApp was skipped in silence and the CLI
// printed "no findings" for it. TokenContract is what fungible tokens, NFT
// collections and AMM pools extend -- the contracts that hold money.
//
// `setFeeRecipient` writes an unconstrained @method argument straight to state.
// If this fixture stops firing, the gate has regressed and an entire class of
// contract is invisible again.
import { TokenContract, method, state, State, PublicKey, AccountUpdateForest } from 'o1js';

export class FungibleToken extends TokenContract {
  @state(PublicKey) feeRecipient = State<PublicKey>();

  async approveBase(forest: AccountUpdateForest) {
    forest.isEmpty().assertFalse();
  }

  @method async setFeeRecipient(recipient: PublicKey) {
    this.feeRecipient.set(recipient);
  }
}
