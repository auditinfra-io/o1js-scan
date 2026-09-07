// @scan-as src/lib/registry.ts
// @recall-rule NONE
// @recall-expect-absent O1JS_UNCONSTRAINED_WITNESS
//
// The gate widened to TokenContract in 0.20.0; it must not widen to anything
// whose name merely ends in "Contract". This class imports o1js and writes an
// unconstrained argument to a field, but it extends a local base that has
// nothing to do with o1js, so there is no circuit here and nothing to report.
import { Field, method } from 'o1js';

class ContractRegistry {}

export class TokenRegistryContract extends ContractRegistry {
  entries: Field[] = [];

  @method async setEntry(value: Field) {
    this.entries[0] = value;
  }
}
