package cs.au.athena.athena.bulletinboard;

import cs.au.athena.athena.distributed.SigmaCommonDistributed;
import cs.au.athena.dao.bulletinboard.CombinedCiphertextAndProof;
import cs.au.athena.dao.bulletinboard.DecryptionShareAndProof;
import cs.au.athena.dao.bulletinboard.PfrPhaseOne;
import cs.au.athena.dao.bulletinboard.PfrPhaseTwo;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiConsumer;

public class VerifyingBulletinBoardV2_0 {
    BulletinBoardV2_0 bb;

    List<CompletableFuture<Void>> pfrPhaseOneOnCompletedFutures;
    List<CompletableFuture<Void>> pfrPhaseTwoOnCompletedFutures;

    public VerifyingBulletinBoardV2_0(BulletinBoardV2_0 bb) {
        this.bb = bb;

        init();
    }

    private void init() {
        for(int i = 0; i < bb.retrieveTallierCount(); i++) {
            pfrPhaseOneOnCompletedFutures.add(new CompletableFuture<>());
        }
    }

    private int getThreshold(){
        return bb.retrieveK() + 1;
    }

    public synchronized int publishPfrPhaseOneEntry(int tallierIndex, List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof) {
        int index = bb.publishPfrPhaseOneEntry(tallierIndex, listOfCombinedCiphertextAndProof);
        pfrPhaseOneOnCompletedFutures.get(index).complete(null);

        return index;
    }

    // Return a Pfr with k+1 valid elements
    public CompletableFuture<PfrPhaseOne> retrieveValidThresholdPfrPhaseOne() {
        int tallierCount = bb.retrieveTallierCount();

        PfrPhaseOne newPfrPhaseOne = new PfrPhaseOne(this.getThreshold());
        CompletableFuture<PfrPhaseOne> resultFuture = CompletableFuture.completedFuture(newPfrPhaseOne);

        // Build a chain of completable futures, that verify the messages as they are posted.
        // It sends the growing list down the cain
        // When the list is k+1, It completes validPfrPhaseOneFuture
        CompletableFuture<PfrPhaseOne> futureChain = CompletableFuture.completedFuture(new PfrPhaseOne(tallierCount));
        for (int i = 0; i < tallierCount; i++) {

            int finalI = i;
            // When the i'th message is published
            CompletableFuture<Void> onMessage = pfrPhaseOneOnCompletedFutures.get(i);
            futureChain = futureChain.thenCombine(onMessage, (PfrPhaseOne pfrPhaseOne, Void onMessage_i) -> {

                // Retrieve the message
                Pair<Integer, List<CombinedCiphertextAndProof>> pair = bb.pfrPhaseOne.get(finalI);

                // Verify
                boolean isValid = SigmaCommonDistributed.verifyHomoComb(bb.ballots, pair.getRight(), bb.retrievePK(), bb.retrieveKappa());

                // Grow list if valid
                if(isValid) {
                    pfrPhaseOne.add(pair);
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

    public void publishPfrPhaseTwoEntry(int tallierIndex, List<DecryptionShareAndProof> decryptionShareAndProof) {
        bb.publishPfrPhaseTwoEntry(tallierIndex, decryptionShareAndProof);
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
            int finalI = i;

            // When the i'th message is published
            CompletableFuture<Void> onMessage = pfrPhaseTwoOnCompletedFutures.get(i);
            futureChain = futureChain.thenCombine(onMessage, (PfrPhaseTwo pfrPhaseTwo, Void onMessage_i) -> {

                // Retrieve the message
                Pair<Integer, List<DecryptionShareAndProof>> pair = bb.pfrPhaseTwo.get(finalI);

                // Verify
                Integer tallierIndex = pair.getLeft();
                ElGamalPK pk_j = bb.retrievePKShare(tallierIndex);
                boolean isValid = SigmaCommonDistributed.verifyDecryption(ciphertexts, pair.getRight(), pk_j, bb.retrieveKappa());

                // Grow list if valid
                if(isValid) {
                    pfrPhaseTwo.add(pair);
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
