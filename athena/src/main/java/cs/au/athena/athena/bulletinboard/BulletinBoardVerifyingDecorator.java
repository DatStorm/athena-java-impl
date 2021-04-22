package cs.au.athena.athena.bulletinboard;

import cs.au.athena.dao.bulletinboard.CombinedCiphertextAndProof;
import cs.au.athena.dao.bulletinboard.PfrPhaseOne;
import cs.au.athena.sigma.Sigma4;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.concurrent.CompletableFuture;

public class BulletinBoardVerifyingDecorator {
    BulletinBoardV2_0 bb;
    int threshold;

    PfrPhaseOne validPfrPhaseOne;
    CompletableFuture<PfrPhaseOne> validPfrPhaseOneFuture;

    public BulletinBoardVerifyingDecorator(BulletinBoardV2_0 bb, int threshold) {
        this.bb = bb;
        this.threshold = threshold;
        this.validPfrPhaseOne = new PfrPhaseOne(threshold+1);

        init();
    }

    private void init() {
        // Add a listener
        // Verifies the pfr as it is updated.
        // If valid, add to validPfrPhaseOne.
        // When k+1, complete future and stop.
        CompletableFuture<PfrPhaseOne> pfrPhaseOneFuture = CompletableFuture.completedFuture(null);

        // Init
        for(int i = 0; i < tallierCount; i++) {
            //
            CompletableFuture<Pair<Integer, List<CombinedCiphertextAndProof>>> publicationFuture = new CompletableFuture<>();
            publications.add(publicationFuture);

            f = f.thenApply((PfrPhaseOne pfrPhaseOne) -> {
                // If pfr is not correct size, check next publication. If valid, add to pfr
                if(pfrPhaseOne.size() < threshold+1) {
                    //Verify next


                    Pair<Integer, List<CombinedCiphertextAndProof>> publication = publicationFuture.join();
                    boolean isValid = Verify(publication.getRight(), pk, kappa);

                    // Add to list if valid
                    if(isValid) {
                        pfrPhaseOne.add(publication);
                    }

                }

                // Return the possebly updated pfr
                return pfrPhaseOne; /// TODO: not correct
            });
        }



















        bb.addPfrPhaseOneListener((Integer index) -> {


            // TODO: This could be replaced with a call to removePfrPhaseOneListener after completing the future
            // If enough valid have been found. Skip.
            if(validPfrPhaseOne.size() >= threshold+1) {
                return;
            }

            // Verifies the pfr as it is updated.
            Pair<Integer, List<CombinedCiphertextAndProof>> pair = bb.pfrPhaseOne.get(index);
            boolean isValid = Sigma4.VerifyAll(pair); // Sigma4.Verify(...)

            // If valid, add to validPfrPhaseOne.
            if(isValid) {
                validPfrPhaseOne.add(pair);
            }

            // When k+1, complete future and stop.
            if(validPfrPhaseOne.size() >= threshold+1) {
                validPfrPhaseOneFuture.complete(validPfrPhaseOne);
            }
        });
    }

    CompletableFuture<PfrPhaseOne> retrieveValidThresholdPfrPhaseOne() {
        return validPfrPhaseOneFuture;
    }


}
