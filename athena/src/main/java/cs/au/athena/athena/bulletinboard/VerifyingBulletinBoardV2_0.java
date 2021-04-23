package cs.au.athena.athena.bulletinboard;

import cs.au.athena.athena.distributed.SigmaCommonDistributed;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.bulletinboard.CombinedCiphertextAndProof;
import cs.au.athena.dao.bulletinboard.PfrPhaseOne;
import cs.au.athena.dao.bulletinboard.PfrPhaseTwo;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.sigma.Sigma4;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;

public class VerifyingBulletinBoardV2_0 {
    BulletinBoardV2_0 bb;

    List<CompletableFuture<Void>> pfrPhaseOneOnCompletedFutures;

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

    public synchronized void publishPfrPhaseOneEntry(int tallierIndex, List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof) {
        bb.publishPfrPhaseOneEntry(tallierIndex, listOfCombinedCiphertextAndProof);

        int nextIndex = 0; //FIXME
        pfrPhaseOneOnCompletedFutures.get(nextIndex).complete(null);
    }

    // Return a Pfr with k+1 valid elements
    public CompletableFuture<PfrPhaseOne> retrieveValidThresholdPfrPhaseOne() {
        int tallierCount = bb.retrieveTallierCount();

        CompletableFuture<PfrPhaseOne> resultFuture = new CompletableFuture<>();

        // Build a chain of completable futures, that verify the messages as they are posted.
        // It sends the growing list down the cain
        // When the list is k+1, It completes validPfrPhaseOneFuture
        CompletableFuture<PfrPhaseOne> f = CompletableFuture.completedFuture(new PfrPhaseOne(tallierCount));
        for (int i = 0; i < tallierCount; i++) {

            int finalI = i;
            // When the i'th message is published
            CompletableFuture<Void> onMessage = pfrPhaseOneOnCompletedFutures.get(i);
            f.thenAcceptBoth(onMessage, (PfrPhaseOne pfrPhaseOne, Void onMessage_i) -> {
                // Retrieve the message
                Pair<Integer, List<CombinedCiphertextAndProof>> pair = bb.pfrPhaseOne.get(finalI);

                // Verify it
                boolean isValid = verifySigma4(bb.ballots, pair.getRight(), bb.retrievePK(), bb.retrieveKappa());

                // Grow list if valid
                if(isValid) {
                    pfrPhaseOne.add(pair);
                }

                // When done, complete and stop the chain of futures
                if(pfrPhaseOne.size() == getThreshold()){
                    resultFuture.complete(pfrPhaseOne);
                    throw new CancellationException("pfr has reached threshold size");
                }
            });
        }

        return resultFuture;
    }

    private static boolean verifySigma4(List<Ballot> ballots, List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof, ElGamalPK pk, int kappa) {
        return SigmaCommonDistributed.verifyHomoComb(ballots,listOfCombinedCiphertextAndProof, pk, kappa);
        int ell = ballots.size();
        Sigma4 sigma4 = new Sigma4();

        // First iteration
        CombinedCiphertextAndProof previousObj = listOfCombinedCiphertextAndProof.get(0);
        Ballot previousBallot = ballots.get(0);

        for (int i = 1; i < ell; i++) {
            CombinedCiphertextAndProof currentObj = listOfCombinedCiphertextAndProof.get(i);
            Ballot currentBallot = ballots.get(i);

            // Make proof statement
            List<Ciphertext> listCombinedCiphertext = Arrays.asList(previousObj.combinedCiphertext, currentObj.combinedCiphertext);
            List<Ciphertext> listCiphertexts = Arrays.asList(previousBallot.getEncryptedNegatedPrivateCredential(), currentBallot.getEncryptedNegatedPrivateCredential());

            // Verify proof
            boolean isValid = sigma4.verifyCombination(pk, listCombinedCiphertext, listCiphertexts, currentObj.proof, kappa);

            if(!isValid) {
                return false;
            }

        }

        return true;
    }

    public CompletableFuture<PfrPhaseTwo> retrieveValidThresholdPfrPhaseTwo() {
        throw new UnsupportedOperationException();
    }

}
