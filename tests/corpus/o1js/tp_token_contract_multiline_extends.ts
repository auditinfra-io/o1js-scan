// @scan-as src/nft/collection.ts
// @recall-rule O1JS_UNCONSTRAINED_WITNESS
// @recall-min-severity medium
//
// SilvanaOne/silvana-lib writes the declaration across two lines, inside a
// factory function:
//
//     class Collection
//       extends TokenContract
//       implements Ownable
//
// The pre-0.20.0 gate required the base class to be spelled SmartContract, on
// the same line as the class name, so this shape missed twice over. That file
// holds 28 @method definitions and scored zero findings.
//
// This comment deliberately does not spell out the old pattern: is_o1js_source
// matches against raw source, comments included, so quoting it here would admit
// the file for the wrong reason and the fixture would pass against the old gate.
import { TokenContract, method, state, State, Field, AccountUpdateForest } from 'o1js';

interface Ownable {}

export function CollectionFactory() {
  class Collection
    extends TokenContract
    implements Ownable
  {
    @state(Field) commitment = State<Field>();

    async approveBase(forest: AccountUpdateForest) {
      forest.isEmpty().assertFalse();
    }

    @method async setCommitment(root: Field) {
      this.commitment.set(root);
    }
  }
  return Collection;
}
