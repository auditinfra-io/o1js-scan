// @recall-rule O1JS_UNVERIFIED_PROOF
// @recall-min-severity high
// @scan-as src/RandoMinaContract.ts
//
// PINNED REGRESSION — confirmed true positive, disclosed.
// iluxonchik/randomina@2d5781a src/RandoMinaContract.ts:69, and the same code
// vendored in iluxonchik/zkLocus@600f406 as
// contracts/src/blockchain/contracts/RandoMinaContract.ts.
//
// `observationProof` is a Proof-typed @method parameter that is never
// .verify()'d. Passing a proof does not verify it, so every field read from
// its publicInput — the claimed sender and network state below — is
// prover-controlled, and the assertions against them are vacuous.
import { SmartContract, Field, Poseidon, method } from 'o1js';

export class RandoMinaContract extends SmartContract {
  @method verifyRandomNumber(observationProof: RandomNumberObservationCircuitProof): void {
    const claimedSender: Field = observationProof.publicInput.sender;
    claimedSender.assertEquals(Poseidon.hash(this.sender.toFields()));

    const claimedNetworkState: Field = observationProof.publicInput.networkState;
    this.network.stakingEpochData.ledger.hash.requireEquals(claimedNetworkState);
  }
}
