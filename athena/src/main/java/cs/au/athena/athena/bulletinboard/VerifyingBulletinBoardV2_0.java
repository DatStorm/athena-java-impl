package cs.au.athena.athena.bulletinboard;

import cs.au.athena.CONSTANTS;
import cs.au.athena.GENERATOR;
import cs.au.athena.athena.distributed.SigmaCommonDistributed;
import cs.au.athena.dao.bulletinboard.*;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.Group;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

public class VerifyingBulletinBoardV2_0 {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("VBB: ");

    private final BulletinBoardV2_0 bb;
    private ElGamalPK pk;
    private final Map<Integer, ElGamalPK> pkShares;

    // How should entries in the pfr be verified?
    BiFunction<Entry<CombinedCiphertextAndProof>, ElGamalPK, Boolean> verifyCombinedCiphertextAndProofEntry;


    /*
     * Being populated in the given method!
     */
    private List<BigInteger> g_vector_vote;
    private List<BigInteger> h_vector_vote;


    public VerifyingBulletinBoardV2_0(BulletinBoardV2_0 bb) {
        this.bb = bb;
        pkShares = new HashMap<>(this.bb.retrieveTallierCount());
    }

    public Pair<List<BigInteger>, List<BigInteger>> retrieve_G_and_H_VectorVote() {
        if (this.g_vector_vote != null || this.h_vector_vote != null) {
            return Pair.of(this.g_vector_vote, this.h_vector_vote);
        } else {
            ElGamalPK pk = retrieveAndVerifyPK();
            //calculate g_vector_vote and h_vector_vote
            List<List<BigInteger>> vectors = GENERATOR.generateRangeProofGenerators(pk, bb.retrieveNumberOfCandidates());
            g_vector_vote = vectors.get(0);
            h_vector_vote = vectors.get(1);
        }

        return Pair.of(g_vector_vote, h_vector_vote);
    }

    // Constructs the method for verifying a Entry<DecryptionShareAndProof>. Used in phases Two and Three
    private Function<Entry<CombinedCiphertextAndProof>, Boolean> constructVerifyHomoCombPfr(List<Ciphertext> ciphertexts) {
        //            logger.info(MARKER, String.format("--".repeat(20) + "> Shit hit the fan: %b" , verify));
        return (entry) -> SigmaCommonDistributed.verifyHomoCombPfr(ciphertexts, entry.getValues(), retrievePKShare(entry.getIndex()), bb.retrieveKappa());
    }

    private Function<Entry<CombinedCiphertextAndProof>, Boolean> constructVerifyHomoCombPfd(List<Ciphertext> ciphertexts) {
        //            logger.info(MARKER, String.format("--".repeat(20) + "> Shit hit the fan: %b" , verify));
        return (entry) -> SigmaCommonDistributed.verifyHomoCombPfd(ciphertexts, entry.getValues(), retrievePKShare(entry.getIndex()), bb.retrieveKappa());
    }

    // Constructs the method for verifying a Entry<DecryptionShareAndProof>. Used in phases Two and Three
    private Function<Entry<DecryptionShareAndProof>, Boolean> constructDecVerify(List<Ciphertext> ciphertexts) {
        return (entry) -> SigmaCommonDistributed.verifyDecryptionShareAndProofs(ciphertexts, entry.getValues(), retrievePKShare(entry.getIndex()), bb.retrieveKappa());
    }

    private int getThreshold() {
        return this.bb.retrieveK() + 1;
    }

    public ElGamalPK retrieveAndVerifyPK() {
        if (this.pk != null) {
            return this.pk;
        }

        Group group = bb.retrieveGroup();
        int kappa = bb.retrieveKappa();
        BigInteger h = BigInteger.ONE;

        // For every tallier
        for (int tallierIndex = 1; tallierIndex <= bb.retrieveTallierCount(); tallierIndex++) {
            // Get pk share and proof
            List<CommitmentAndProof> commitmentAndProofs = bb.retrievePolynomialCommitmentsAndProofs(tallierIndex).join();

            // Verify degree of polynomial
            if (commitmentAndProofs.size() != getThreshold()) {
                throw new RuntimeException(String.format("Malicious tallier detected. Tallier T%d published a polynomial of wrong degree", tallierIndex));
            }

            boolean isValid = SigmaCommonDistributed.verifyPK(commitmentAndProofs, group, kappa);

            if (!isValid) {
                logger.info(MARKER, String.format("T%d: Verifying: %s", tallierIndex, commitmentAndProofs));
                throw new RuntimeException(String.format("Malicious tallier detected. Proof by Tallier T%d was invalid in the PK generation", tallierIndex));
            }
            BigInteger commitment = getZeroCommitment(commitmentAndProofs);
            h = h.multiply(commitment).mod(group.p);
        }

        pk = new ElGamalPK(h, group);
        return pk;
    }

    // Compute and return the public key share h_j=g^P(j) from the committed polynomials
    public ElGamalPK retrievePKShare(int j) {
        if (this.pkShares.containsKey(j)) {
            return this.pkShares.get(j);
        }

        Group group = bb.retrieveGroup();
        BigInteger publicKeyShare = BigInteger.ONE;
        Map<Integer, CompletableFuture<List<CommitmentAndProof>>> commitmentAndProofsMap = bb.retrievePolynomialCommitmentsAndProofs();

        // Iterate all commitments
        for (int index = 1; index <= commitmentAndProofsMap.keySet().size(); index++) {
            List<CommitmentAndProof> commitmentAndProofs = commitmentAndProofsMap.get(index).join();

            // For each commitment in the polynomial
            for (int ell = 0; ell < getThreshold(); ell++) {
                BigInteger j_pow_ell = BigInteger.valueOf(j).pow(ell);
                BigInteger commitment = commitmentAndProofs.get(ell).commitment;

                publicKeyShare = publicKeyShare.multiply(commitment.modPow(j_pow_ell, group.p)).mod(group.p);
            }
        }

        ElGamalPK pkShare = new ElGamalPK(publicKeyShare, group);
        pkShares.put(j, pkShare);
        return pkShare;
    }

    private BigInteger getZeroCommitment(List<CommitmentAndProof> commitmentAndProofs) {
        return commitmentAndProofs.get(0).commitment;
    }

    // Generic function containing the common code in the retrieveValidThreshold... functions

    /**
     * @param pfPhase     the bulletin board pfr to retrieve from
     * @param verifyEntry a method that verifies the entries in the pfr
     * @return A future that is completed with threshold valid entries, when these are available on the BB
     */
    private <T> CompletableFuture<PfPhase<T>> retrieveValidThresholdPfPhase(BulletinBoardV2_0 bb, PfPhase<T> pfPhase, Function<Entry<T>, Boolean> verifyEntry) {
        int tallierCount = bb.retrieveTallierCount();

        logger.info(MARKER, String.format("Waiting for threshold=%d, valid entries (TallierCount=%d)", getThreshold(), tallierCount));


        CompletableFuture<PfPhase<T>> resultFuture = new CompletableFuture<>();
        // Build a chain of completable futures, that verify the messages as they are posted.
        // It sends the growing list down the cain
        // When the list is k+1, It completes validPfrPhaseOneFuture

        // Start chain with empty input
        CompletableFuture<PfPhase<T>> futureChain = CompletableFuture.completedFuture(new PfPhase<>(this.getThreshold()));

        for (int i = 0; i < tallierCount; i++) {
            // When then ext entry is available
            CompletableFuture<Entry<T>> entryFuture = pfPhase.getEntryFuture(i);

            // Continue chain, by verifying the entry and adding to Pfr
            futureChain = futureChain.thenCombine(entryFuture, (PfPhase<T> chainPfPhase, Entry<T> entry) -> {

                // Verify entry
                boolean isValid = verifyEntry.apply(entry);

                // Grow list if valid
                if (isValid) {
                    chainPfPhase.add(entry);
                    //logger.info(MARKER, String.format("Received valid entry from T%d. Pf size is now %d", entry.getIndex(), chainPfPhase.size()));
                } else {
                    //logger.info(MARKER, String.format("Received invalid entry from T%d. Pf size is now %d", entry.getIndex(), chainPfPhase.size()));
                }

                // When done, complete and stop the chain of futures
                if (chainPfPhase.size() == getThreshold()) {
                    resultFuture.complete(chainPfPhase);
                    throw new CancellationException("pfr has reached threshold size. Do not wait for the remaining talliers");
                }

                return chainPfPhase;
            });
        }

        return resultFuture;
    }

    public CompletableFuture<PfPhase<CombinedCiphertextAndProof>> retrieveValidThresholdPfrPhaseOne(List<Ciphertext> encryptedNegatedPrivateCredentials) {
        CompletableFuture<PfPhase<CombinedCiphertextAndProof>> pfPhaseCompletableFuture = retrieveValidThresholdPfPhase(bb, bb.retrievePfrPhaseOne(), constructVerifyHomoCombPfr(encryptedNegatedPrivateCredentials));
        pfPhaseCompletableFuture.thenAccept((pfPhase) -> logger.error(MARKER, String.format(fr("-- PFR-ONE -> entries: %s"), pfPhase.getEntries().stream().map(Entry::getIndex).collect(Collectors.toList()))));

        return pfPhaseCompletableFuture;
    }


    public CompletableFuture<PfPhase<DecryptionShareAndProof>> retrieveValidThresholdPfrPhaseTwo(List<Ciphertext> ciphertexts) {
        CompletableFuture<PfPhase<DecryptionShareAndProof>> pfPhaseCompletableFuture = retrieveValidThresholdPfPhase(bb, bb.retrievePfrPhaseTwo(), constructDecVerify(ciphertexts));
        pfPhaseCompletableFuture.thenAccept((pfPhase) -> logger.error(MARKER, String.format(fr("-- PFR-TWO -> entries: %s"), pfPhase.getEntries().stream().map(Entry::getIndex).collect(Collectors.toList()))));
        return pfPhaseCompletableFuture;
    }

    public CompletableFuture<PfPhase<CombinedCiphertextAndProof>> retrieveValidThresholdPfdPhaseOne(List<Ciphertext> combinedCredentials) {
        CompletableFuture<PfPhase<CombinedCiphertextAndProof>> pfPhaseCompletableFuture = retrieveValidThresholdPfPhase(bb, bb.retrievePfdPhaseOne(), constructVerifyHomoCombPfd(combinedCredentials));
        pfPhaseCompletableFuture.thenAccept((pfPhase) -> logger.error(MARKER, String.format(fy("-- PFD-ONE -> entries: %s"), pfPhase.getEntries().stream().map(Entry::getIndex).collect(Collectors.toList()))));

        return pfPhaseCompletableFuture;
    }

    public CompletableFuture<PfPhase<DecryptionShareAndProof>> retrieveValidThresholdPfdPhaseTwo(List<Ciphertext> ciphertexts) {
        CompletableFuture<PfPhase<DecryptionShareAndProof>> pfPhaseCompletableFuture = retrieveValidThresholdPfPhase(bb, bb.retrievePfdPhaseTwo(), constructDecVerify(ciphertexts));
        pfPhaseCompletableFuture.thenAccept((pfPhase) -> logger.error(MARKER, String.format(fy("-- PFD-TWO -> entries: %s"), pfPhase.getEntries().stream().map(Entry::getIndex).collect(Collectors.toList()))));

        return pfPhaseCompletableFuture;
    }

    public CompletableFuture<PfPhase<DecryptionShareAndProof>> retrieveValidThresholdPfdPhaseThree(List<Ciphertext> ciphertexts) {
        CompletableFuture<PfPhase<DecryptionShareAndProof>> pfPhaseCompletableFuture = retrieveValidThresholdPfPhase(bb, bb.retrievePfdPhaseThree(), constructDecVerify(ciphertexts));
        pfPhaseCompletableFuture.thenAccept((pfPhase) -> logger.error(MARKER, String.format(fy("-- PFD-THR -> entries: %s"), pfPhase.getEntries().stream().map(Entry::getIndex).collect(Collectors.toList()))));

        return pfPhaseCompletableFuture;
    }



    public Map<Integer, CompletableFuture<MixedBallotsAndProof>> retrieveValidMixedBallotAndProofs(List<MixBallot> initialMixBallots) {
        Map<Integer, CompletableFuture<MixedBallotsAndProof>> mixedBallotAndProofs = bb.retrieveMixedBallotAndProofs();

        // For each tallier
        List<MixBallot> previousMixBallots = initialMixBallots;
        for (int i = 1; i < bb.retrieveTallierCount(); i++) {
            MixedBallotsAndProof mixedBallotsAndProof = mixedBallotAndProofs.get(i).join();

            // Verify
            MixStatement statement = new MixStatement(previousMixBallots, mixedBallotsAndProof.mixedBallots);
            boolean isValidMix = SigmaCommonDistributed.verifyMix(statement, mixedBallotsAndProof.mixProof, pk, bb.retrieveKappa());

            if (!isValidMix) {
                throw new RuntimeException(String.format("Malicious tallier T%d detected during mixing of the ballots", i));
            }

            previousMixBallots = mixedBallotsAndProof.mixedBallots;
        }

        // If a mix was invalid, we have thrown an exception before this point.

        // Therefore all proofs are valid
        return mixedBallotAndProofs;
    }

    private String fr(String s) { return CONSTANTS.ANSI_RED + s + CONSTANTS.ANSI_RESET; }
    private String fy(String s) { return CONSTANTS.ANSI_YELLOW + s + CONSTANTS.ANSI_RESET;  }
}
