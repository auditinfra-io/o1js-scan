// @recall-rule O1JS_VACUOUS_ASSERT
// @recall-min-severity high
// @scan-as contracts/src/blockchain/contracts/experiments/DeployerVerificationSC.ts
//
// PINNED REGRESSION — confirmed true positive (calibration Wave 2).
// iluxonchik/zkLocus@600f4068 DeployerVerificationSC.requireDeployedBySender —
// `senderDigest.assertEquals(senderDigest)` is a self-comparison typo
// (meant to bind against claimedDeployeeAddrDigest).
import { SmartContract, method, Field, PublicKey, Poseidon } from 'o1js';

export class DeployerVerificationSC extends SmartContract {
  @method async requireDeployedBySender(
    deployedSCAddr: PublicKey,
    claimedDeployeeAddrDigest: Field,
  ) {
    const senderDigest: Field = Poseidon.hash(
      this.sender.getAndRequireSignature().toFields(),
    );
    senderDigest.assertEquals(senderDigest);
  }
}
