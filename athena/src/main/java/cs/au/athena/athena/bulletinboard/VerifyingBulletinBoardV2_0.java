package cs.au.athena.athena.bulletinboard;

import cs.au.athena.GENERATOR;
import cs.au.athena.athena.distributed.SigmaCommonDistributed;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.bulletinboard.*;
import cs.au.athena.dao.mixnet.MixBallot;
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

    public Pair<List<BigInteger>,List<BigInteger>>  retrieve_G_and_H_VectorVote() {
        if(this.g_vector_vote != null || this.h_vector_vote != null) {
            return Pair.of(this.g_vector_vote, this.h_vector_vote);
        } else {
            ElGamalPK pk = retrieveAndVerifyPK();
            //calculate g_vector_vote and h_vector_vote
            List<List<BigInteger>> vectors = GENERATOR.generateRangeProofGenerators(pk, bb.retrieveNumberOfCandidates());
            g_vector_vote = vectors.get(0);
            h_vector_vote = vectors.get(1);
        }

        return Pair.of(g_vector_vote,h_vector_vote);
    }

    // Constructs the method for verifying a Entry<DecryptionShareAndProof>. Used in phases Two and Three
    private Function<Entry<CombinedCiphertextAndProof>, Boolean> constructHomoVerify(List<Ciphertext> ciphertexts) {
        //            logger.info(MARKER, String.format("--".repeat(20) + "> Shit hit the fan: %b" , verify));
        return (entry) -> SigmaCommonDistributed.verifyHomoComb(ciphertexts, entry.getValues(), retrievePKShare(entry.getIndex()), bb.retrieveKappa());
    }

    // Constructs the method for verifying a Entry<DecryptionShareAndProof>. Used in phases Two and Three
    private Function<Entry<DecryptionShareAndProof>, Boolean> constructDecVerify(List<Ciphertext> ciphertexts) {
        return (entry) -> SigmaCommonDistributed.verifyDecryption(ciphertexts, entry.getValues(), retrievePKShare(entry.getIndex()), bb.retrieveKappa());
    }

    private int getThreshold(){
        return this.bb.retrieveK() + 1;
    }

    public ElGamalPK retrieveAndVerifyPK() {
        if(this.pk != null) {
            return this.pk;
        }

        Group group = bb.retrieveGroup();
        int kappa = bb.retrieveKappa();
        BigInteger h = BigInteger.ONE;

        // For every tallier
        for (int tallierIndex = 1; tallierIndex <= bb.retrieveTallierCount(); tallierIndex++) {
            // Get pk share and proof
            List<CommitmentAndProof> commitmentAndProofs =  bb.retrievePolynomialCommitmentsAndProofs(tallierIndex).join();

            // Verify degree of polynomial
            if(commitmentAndProofs.size() != getThreshold()) {
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
        if(this.pkShares.containsKey(j)) {
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

    private BigInteger getZeroCommitment(List<CommitmentAndProof> commitmentAndProofs){
        return commitmentAndProofs.get(0).commitment;
    }

    // Generic function containing the common code in the retrieveValidThreshold... functions/**

    /**
     * @param pfrPhase the bulletin board pfr to retrieve from
     * @param verifyEntry a method that verifies the entries in the pfr
     * @return A fytyre that is completed with threshold valid entries, when these are available on the BB
     */
    private <T> CompletableFuture<PfPhase<T>> retrieveValidThresholdPfrPhase(BulletinBoardV2_0 bb, PfPhase<T> pfrPhase, Function<Entry<T>, Boolean> verifyEntry) {
        int tallierCount = bb.retrieveTallierCount();

        logger.info(MARKER, String.format("Waiting for threshold=%d, valid entries", getThreshold()));


        CompletableFuture<PfPhase<T>> resultFuture = new CompletableFuture<>();
        // Build a chain of completable futures, that verify the messages as they are posted.
        // It sends the growing list down the cain
        // When the list is k+1, It completes validPfrPhaseOneFuture

        // Start chain with empty input
        CompletableFuture<PfPhase<T>> futureChain = CompletableFuture.completedFuture(new PfPhase<>(this.getThreshold()));

        for (int i = 0; i < tallierCount; i++) {
            // When then ext entry is available
            CompletableFuture<Entry<T>> entryFuture = pfrPhase.getFuture(i);

            // Continue chain, by verifying the entry and adding to Pfr
            futureChain = futureChain.thenCombine(entryFuture, (PfPhase<T> chainPfrPhase, Entry<T> entry) -> {

                // Verify entry
                boolean isValid = verifyEntry.apply(entry);

                // Grow list if valid
                if(isValid) {
                    chainPfrPhase.add(entry);
                    logger.info(MARKER, String.format("Received valid entry from T%d. Pf size is now %d", entry.getIndex(), chainPfrPhase.size()));
                } else {
                    logger.info(MARKER, String.format("Received invalid entry from T%d. Pf size is now %d", entry.getIndex(), chainPfrPhase.size()));
                }

                // When done, complete and stop the chain of futures
                if(chainPfrPhase.size() == getThreshold()){
                    logger.info(MARKER, "futureChain pf size reached the threshold");

                    resultFuture.complete(chainPfrPhase);
                    throw new CancellationException("pfr has reached threshold size");
                }

                return chainPfrPhase;
            });
        }

        return resultFuture;
    }

    public CompletableFuture<PfPhase<CombinedCiphertextAndProof>> retrieveValidThresholdPfrPhaseOne() {
        List<Ciphertext> encryptedNegatedPrivateCredentials = bb.retrieveBallots().stream()
                .map(Ballot::getEncryptedNegatedPrivateCredential)
                .collect(Collectors.toList());

        return retrieveValidThresholdPfrPhase(bb, bb.retrievePfrPhaseOne(), constructHomoVerify(encryptedNegatedPrivateCredentials));
    }

    public CompletableFuture<PfPhase<DecryptionShareAndProof>> retrieveValidThresholdPfrPhaseTwo(List<Ciphertext> ciphertexts) {
        return retrieveValidThresholdPfrPhase(bb, bb.retrievePfrPhaseTwo(), constructDecVerify(ciphertexts));
    }

    public CompletableFuture<PfPhase<CombinedCiphertextAndProof>> retrieveValidThresholdPfdPhaseOne() {
        List<Ciphertext> combinedCiphertexts = bb.retrieveMixedBallots().stream()
                .map(MixBallot::getCombinedCredential)
                .collect(Collectors.toList());

        return retrieveValidThresholdPfrPhase(bb, bb.retrievePfdPhaseOne(), constructHomoVerify(combinedCiphertexts));
    }

    public CompletableFuture<PfPhase<DecryptionShareAndProof>> retrieveValidThresholdPfdPhaseTwo(List<Ciphertext> ciphertexts) {
        return retrieveValidThresholdPfrPhase(bb, bb.retrievePfdPhaseTwo(), constructDecVerify(ciphertexts));
    }

    public CompletableFuture<PfPhase<DecryptionShareAndProof>> retrieveValidThresholdPfdPhaseThree(List<Ciphertext> ciphertexts) {
        return retrieveValidThresholdPfrPhase(bb, bb.retrievePfdPhaseThree(), constructDecVerify(ciphertexts));
    }
}
