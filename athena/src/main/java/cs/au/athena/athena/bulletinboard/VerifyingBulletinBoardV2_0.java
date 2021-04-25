package cs.au.athena.athena.bulletinboard;

import cs.au.athena.athena.distributed.SigmaCommonDistributed;
import cs.au.athena.dao.bulletinboard.*;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.Group;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;

public class VerifyingBulletinBoardV2_0 {
    BulletinBoardV2_0 bb;

    public VerifyingBulletinBoardV2_0(BulletinBoardV2_0 bb) {
        this.bb = bb;
    }

    private int getThreshold(){
        return bb.retrieveK() + 1;
    }


    public ElGamalPK retrieveAndVerifyPK() {
        Group group = bb.retrieveGroup();
        int kappa = bb.retrieveKappa();

        BigInteger h = BigInteger.ONE;

        // For every tallier
        for (int tallierIndex = 0; tallierIndex < bb.retrieveTallierCount(); tallierIndex++) {

            // Get pk share and proof
            List<CommitmentAndProof> commitmentAndProofs =  bb.retrieveCommitmentsAndProofs(tallierIndex).join();

            // Verify degree of polynomial
            if(commitmentAndProofs.size() != bb.retrieveK()+1) {
                throw new RuntimeException(String.format("Malicious tallier detected. Tallier %d published a polynomial of wrong degree", tallierIndex));

            }

            boolean isValid = SigmaCommonDistributed.verifyPK(commitmentAndProofs, group, kappa);

            if (!isValid) {
                throw new RuntimeException(String.format("Malicious tallier detected. Proof of Tallier %d was invalid", tallierIndex));
            }
            BigInteger commitment = getSecret(commitmentAndProofs);
            h = h.multiply(commitment).mod(group.p);
        }

        return new ElGamalPK(h, group);


    }

    private BigInteger getSecret(List<CommitmentAndProof> commitmentAndProofs){
        return commitmentAndProofs.get(0).commitment;
    }

    public CompletableFuture<PfrPhase<CombinedCiphertextAndProof>> retrieveValidThresholdPfrPhaseOne() {
        PfrPhase<CombinedCiphertextAndProof> pfrPhaseOne = bb.retrievePfrPhaseOne();
        int tallierCount = bb.retrieveTallierCount();

        CompletableFuture<PfrPhase<CombinedCiphertextAndProof>> resultFuture = new CompletableFuture<>();
        // Build a chain of completable futures, that verify the messages as they are posted.
        // It sends the growing list down the cain
        // When the list is k+1, It completes validPfrPhaseOneFuture

        // Start chain with empty input
        CompletableFuture<PfrPhase<CombinedCiphertextAndProof>> futureChain = CompletableFuture.completedFuture(new PfrPhase<>(this.getThreshold()));

        for (int i = 0; i < tallierCount; i++) {
            // When then ext entry is available
            CompletableFuture<Entry<CombinedCiphertextAndProof>> future = pfrPhaseOne.getFuture(i);

            // Continue chain, by verifying the entry and adding to Pfr
            futureChain = futureChain.thenCombine(future, (PfrPhase<CombinedCiphertextAndProof> chainPfrPhase, Entry<CombinedCiphertextAndProof> entry) -> {

                // Verify
                boolean isValid = SigmaCommonDistributed.verifyHomoComb(bb.ballots, entry.getValues(), bb.retrievePK(), bb.retrieveKappa());

                // Grow list if valid
                if(isValid) {
                    chainPfrPhase.add(entry);
                }

                // When done, complete and stop the chain of futures
                if(chainPfrPhase.size() == getThreshold()){
                    resultFuture.complete(chainPfrPhase);
                    throw new CancellationException("pfr has reached threshold size");
                }

                return chainPfrPhase;
            });
        }

        return resultFuture;
    }

    public CompletableFuture<PfrPhase<DecryptionShareAndProof>> retrieveValidThresholdPfrPhaseTwo(List<Ciphertext> ciphertexts) {
        PfrPhase<DecryptionShareAndProof> pfrPhaseTwo = bb.retrievePfrPhaseTwo();
        int tallierCount = bb.retrieveTallierCount();

        PfrPhase<DecryptionShareAndProof> newPfrPhaseTwo = new PfrPhase<>(this.getThreshold());
        CompletableFuture<PfrPhase<DecryptionShareAndProof>> resultFuture = CompletableFuture.completedFuture(newPfrPhaseTwo);

        // Build a chain of completable futures, that verify the messages as they are posted.
        // It sends the growing list down the cain
        // When the list is k+1, It completes validPfrPhaseTwoFuture
        CompletableFuture<PfrPhase<DecryptionShareAndProof>> futureChain = CompletableFuture.completedFuture(new PfrPhase<>(tallierCount));
        for (int i = 0; i < tallierCount; i++) {

            // When then ext entry is available
            CompletableFuture<Entry<DecryptionShareAndProof>> future = pfrPhaseTwo.getFuture(i);

            // Continue chain, by verifying the entry and adding to Pfr
            futureChain = futureChain.thenCombine(future,  (PfrPhase<DecryptionShareAndProof> chainPfr, Entry<DecryptionShareAndProof> entry) -> {

                // Verify
                ElGamalPK pk_j = bb.retrievePKShare(entry.getIndex());
                boolean isValid = SigmaCommonDistributed.verifyDecryption(ciphertexts, entry.getValues(), pk_j, bb.retrieveKappa());

                // Grow list if valid
                if(isValid) {
                    chainPfr.add(entry);
                }

                // When done, complete and stop the chain of futures
                if(chainPfr.size() == getThreshold()){
                    resultFuture.complete(chainPfr);
                    throw new CancellationException("pfr has reached threshold size");
                }

                return chainPfr;
            });
        }

        return resultFuture;
    }

}
