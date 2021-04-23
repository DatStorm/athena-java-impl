package cs.au.athena.athena.bulletinboard;

import cs.au.athena.athena.distributed.SigmaCommonDistributed;
import cs.au.athena.dao.bulletinboard.*;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.Group;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;

public class VerifyingBulletinBoardV2_0 {
    BulletinBoardV2_0 bb;

    List<CompletableFuture<PfrPhaseOne.Entry>> pfrPhaseOneOnCompletedFutures;
    List<CompletableFuture<PfrPhaseTwo.Entry>> pfrPhaseTwoOnCompletedFutures;

    public VerifyingBulletinBoardV2_0(BulletinBoardV2_0 bb) {
        this.bb = bb;

        pfrPhaseOneOnCompletedFutures = new ArrayList<>();
        pfrPhaseTwoOnCompletedFutures = new ArrayList<>();

        for(int i = 0; i < bb.retrieveTallierCount(); i++) {
            pfrPhaseOneOnCompletedFutures.add(new CompletableFuture<>());
            pfrPhaseTwoOnCompletedFutures.add(new CompletableFuture<>());
        }
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



    public synchronized int publishPfrPhaseOneEntry(int tallierIndex, List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof) {
        int index = bb.publishPfrPhaseOneEntry(tallierIndex, listOfCombinedCiphertextAndProof);
        PfrPhaseOne.Entry entry = new PfrPhaseOne.Entry(tallierIndex, listOfCombinedCiphertextAndProof);

        pfrPhaseOneOnCompletedFutures.get(index).complete(entry);
        return index;
    }

    public CompletableFuture<PfrPhaseOne> retrieveValidThresholdPfrPhaseOne() {
        int tallierCount = bb.retrieveTallierCount();

        PfrPhaseOne newPfrPhaseOne = new PfrPhaseOne(this.getThreshold());
        CompletableFuture<PfrPhaseOne> resultFuture = CompletableFuture.completedFuture(newPfrPhaseOne);

        // Build a chain of completable futures, that verify the messages as they are posted.
        // It sends the growing list down the cain
        // When the list is k+1, It completes validPfrPhaseOneFuture
        CompletableFuture<PfrPhaseOne> futureChain = CompletableFuture.completedFuture(new PfrPhaseOne(tallierCount));
        for (int i = 0; i < tallierCount; i++) {

            // When the i'th message is published
            CompletableFuture<PfrPhaseOne.Entry> pfrPhaseOneEntryFuture = pfrPhaseOneOnCompletedFutures.get(i);
            futureChain = futureChain.thenCombine(pfrPhaseOneEntryFuture, (PfrPhaseOne pfrPhaseOne, PfrPhaseOne.Entry entry) -> {

                // Verify
                boolean isValid = SigmaCommonDistributed.verifyHomoComb(bb.ballots, entry.getCombinedCiphertextAndProof(), bb.retrievePK(), bb.retrieveKappa());

                // Grow list if valid
                if(isValid) {
                    pfrPhaseOne.add(entry);
                }

                // When done, complete and stop the chain of futures
                if(pfrPhaseOne.size() == getThreshold()){
                    resultFuture.complete(pfrPhaseOne);
                    throw new CancellationException("pfr has reached threshold size");
                }

                return pfrPhaseOne;
            });
        }

        return resultFuture;
    }

    public int publishPfrPhaseTwoEntry(int tallierIndex, List<DecryptionShareAndProof> decryptionShareAndProof) {
        int index = bb.publishPfrPhaseTwoEntry(tallierIndex, decryptionShareAndProof);
        PfrPhaseTwo.Entry entry = new PfrPhaseTwo.Entry(tallierIndex, decryptionShareAndProof);

        pfrPhaseTwoOnCompletedFutures.get(index).complete(entry);
        return index;
    }

    public CompletableFuture<PfrPhaseTwo> retrieveValidThresholdPfrPhaseTwo(List<Ciphertext> ciphertexts) {
        int tallierCount = bb.retrieveTallierCount();

        PfrPhaseTwo newPfrPhaseTwo = new PfrPhaseTwo(this.getThreshold());
        CompletableFuture<PfrPhaseTwo> resultFuture = CompletableFuture.completedFuture(newPfrPhaseTwo);

        // Build a chain of completable futures, that verify the messages as they are posted.
        // It sends the growing list down the cain
        // When the list is k+1, It completes validPfrPhaseTwoFuture
        CompletableFuture<PfrPhaseTwo> futureChain = CompletableFuture.completedFuture(new PfrPhaseTwo(tallierCount));
        for (int i = 0; i < tallierCount; i++) {

            // When the i'th message is published
            CompletableFuture<PfrPhaseTwo.Entry> pfrPhaseTwoEntryFuture = pfrPhaseTwoOnCompletedFutures.get(i);
            futureChain = futureChain.thenCombine(pfrPhaseTwoEntryFuture,  (PfrPhaseTwo pfrPhaseTwo, PfrPhaseTwo.Entry entry) -> {

                // Verify
                ElGamalPK pk_j = bb.retrievePKShare(entry.getIndex());
                boolean isValid = SigmaCommonDistributed.verifyDecryption(ciphertexts, entry.getDecryptionShareAndProofs(), pk_j, bb.retrieveKappa());

                // Grow list if valid
                if(isValid) {
                    pfrPhaseTwo.add(entry);
                }

                // When done, complete and stop the chain of futures
                if(pfrPhaseTwo.size() == getThreshold()){
                    resultFuture.complete(pfrPhaseTwo);
                    throw new CancellationException("pfr has reached threshold size");
                }

                return pfrPhaseTwo;
            });
        }

        return resultFuture;
    }

}
