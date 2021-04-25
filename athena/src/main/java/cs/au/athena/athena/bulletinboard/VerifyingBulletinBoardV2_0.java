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
import java.util.function.BiFunction;
import java.util.function.Function;

public class VerifyingBulletinBoardV2_0 {

    private static int getThreshold(BulletinBoardV2_0 bb){
        return bb.retrieveK() + 1;
    }


    public static ElGamalPK retrieveAndVerifyPK(BulletinBoardV2_0 bb) {
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

    private static BigInteger getSecret(List<CommitmentAndProof> commitmentAndProofs){
        return commitmentAndProofs.get(0).commitment;
    }

    // Generic function containing the common code in the retrieveValidThreshold... functions/**

    /**
     * @param pfrPhase the bulletin board pfr to retrieve from
     * @param verifyEntry a method that verifies the entries in the pfr
     * @param getPK a method that returns the pk to be used in the verification above
     * @return A fytyre that is completed with threshold valid entries, when these are available on the BB
     */
    private static <T> CompletableFuture<PfrPhase<T>> retrieveValidThreshold(BulletinBoardV2_0 bb, PfrPhase<T> pfrPhase, BiFunction<Entry<T>, ElGamalPK, Boolean> verifyEntry, Function<Entry<T>, ElGamalPK> getPK) {
        int tallierCount = bb.retrieveTallierCount();

        CompletableFuture<PfrPhase<T>> resultFuture = new CompletableFuture<>();
        // Build a chain of completable futures, that verify the messages as they are posted.
        // It sends the growing list down the cain
        // When the list is k+1, It completes validPfrPhaseOneFuture

        // Start chain with empty input
        CompletableFuture<PfrPhase<T>> futureChain = CompletableFuture.completedFuture(new PfrPhase<>(getThreshold(bb)));

        for (int i = 0; i < tallierCount; i++) {
            // When then ext entry is available
            CompletableFuture<Entry<T>> future = pfrPhase.getFuture(i);

            // Continue chain, by verifying the entry and adding to Pfr
            futureChain = futureChain.thenCombine(future, (PfrPhase<T> chainPfrPhase, Entry<T> entry) -> {

                // Verify
                ElGamalPK pk = getPK.apply(entry);
                boolean isValid = verifyEntry.apply(entry, pk);

                // Grow list if valid
                if(isValid) {
                    chainPfrPhase.add(entry);
                }

                // When done, complete and stop the chain of futures
                if(chainPfrPhase.size() == getThreshold(bb)){
                    resultFuture.complete(chainPfrPhase);
                    throw new CancellationException("pfr has reached threshold size");
                }

                return chainPfrPhase;
            });
        }

        return resultFuture;
    }

    public static CompletableFuture<PfrPhase<CombinedCiphertextAndProof>> retrieveValidThresholdPfrPhaseOne(BulletinBoardV2_0 bb) {
        // How should entries in the pfr be verified?
        BiFunction<Entry<CombinedCiphertextAndProof>, ElGamalPK, Boolean> verifyEntry =
                (entry, pk) -> SigmaCommonDistributed.verifyHomoComb(bb.ballots, entry.getValues(), pk, bb.retrieveKappa());

        // Use the global pk for all entries
        ElGamalPK pk = bb.retrievePK();

        // Delegate
        PfrPhase<CombinedCiphertextAndProof> pfrPhaseOne = bb.retrievePfrPhaseOne();
        return retrieveValidThreshold(bb, pfrPhaseOne, verifyEntry, entry -> pk);
    }

    public static CompletableFuture<PfrPhase<DecryptionShareAndProof>> retrieveValidThresholdPfrPhaseTwo(BulletinBoardV2_0 bb, List<Ciphertext> ciphertexts) {
        // How should entries in the pfr be verified?
        BiFunction<Entry<DecryptionShareAndProof>, ElGamalPK, Boolean> verifyEntry =
                (entry, pk) -> SigmaCommonDistributed.verifyDecryption(ciphertexts, entry.getValues(), pk, bb.retrieveKappa());

        // Use the entries corresponding pk share
        Function<Entry<DecryptionShareAndProof>, ElGamalPK> getPK = entry -> bb.retrievePKShare(entry.getIndex());

        // Delegate
        return retrieveValidThreshold(bb, bb.retrievePfrPhaseTwo(), verifyEntry, getPK);

    }

}
