package cs.au.athena.athena;

import cs.au.athena.GENERATOR;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.athena.bulletinboard.VerifyingBulletinBoardV2_0;
import cs.au.athena.athena.distributed.AthenaDistributed;
import cs.au.athena.dao.athena.*;
import cs.au.athena.dao.bulletinboard.CombinedCiphertextAndProof;
import cs.au.athena.dao.bulletinboard.DecryptionShareAndProof;
import cs.au.athena.dao.bulletinboard.PfPhase;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.factory.AthenaFactory;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

public class AthenaVerify {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("ATHENA-VERIFY");

    private BulletinBoardV2_0 bb;
    private VerifyingBulletinBoardV2_0 vbb;

    private AthenaVerify() {
    }


    public boolean Verify() {
        logger.info(MARKER, "AthenaVerify.Verify[started]");
        //Fetch from bulletin board
        int nc = this.bb.retrieveNumberOfCandidates();
        Map<Integer, CompletableFuture<Map<Integer, Integer>>> officialTallys = this.bb.retrieveOfficialTally();

        // Retrieve and verify ElGamal PK produced form the polynomial of the talliers
        ElGamalPK pk = vbb.retrieveAndVerifyPK();

        // Check that the number of candidates nc in the given election does not exceed the maximum number mc.
        int mc = bb.retrieveMaxCandidates();
        if (nc > mc) { // if nc > mc
            System.err.println("AthenaVerify:=> ERROR: nc= " + nc + " > mc=" + mc);
            return false;
        }

        // Verify range proof generators
        boolean isValid = verifyRangeProofGenerators(pk);
        if(!isValid) {
            System.err.println("AthenaVerify:=> ERROR: verifyRangeProofGenerators failed");
            return false;
        }


        // Ground truth
        Map<Integer, Integer> tally = calculateTally(pk, nc);


        // is my "tally" equal to k+1 "officialTally";
        int numberOfCorrectTallies = 0;
        for (Map.Entry<Integer, CompletableFuture<Map<Integer, Integer>>> entry : officialTallys.entrySet()) {

            Map<Integer, Integer> officialTally = entry.getValue().join();
            boolean tallierTallyMatchGroundTruth = officialTally.equals(tally);

            if (tallierTallyMatchGroundTruth) {
                numberOfCorrectTallies++;
            } else {
                logger.info(MARKER, String.format("AthenaVerify.Verify[T%d calculated wrong tally!]", entry.getKey()));
            }

            // When k+1 correct official tallys have been published, return true.
            boolean electionIsValid = numberOfCorrectTallies >= bb.retrieveK() + 1;
            if(electionIsValid){
                logger.info(MARKER, "AthenaVerify.Verify[ended] by finding k+1 correct official tallies");
                return true;
            }
        }

        logger.info(MARKER, "AthenaVerify.Verify[ended] without finding k+1 correct official tallies");
        return false;
    }


    private Map<Integer, Integer> calculateTally(ElGamalPK pk, int nc) {
        logger.info(MARKER, "AthenaVerify.Verify.calculateTally[started]");
        /* ********
         * Verify Step 1: check ballot removal
         *********/
        List<Ballot> validBallots = AthenaTally.removeInvalidBallots(pk, this.bb, this.vbb);
        if (validBallots.isEmpty()) {
            System.err.println("AthenaVerify:=> Check 1 failed.");
            throw new RuntimeException();
        }


        /* ********
         * Verify step 2:
         *********/
        List<Ciphertext> encryptedNegatedPrivateCredentials = validBallots
                .stream()
                .map(Ballot::getEncryptedNegatedPrivateCredential)
                .collect(Collectors.toList());

        // Phase I: Nonce private credential
        // Verify homo comb proofs, and get nonced negated private credentials, then Combine shares
        PfPhase<CombinedCiphertextAndProof> validPfrPhaseOne = vbb.retrieveValidThresholdPfrPhaseOne(encryptedNegatedPrivateCredentials).join();
        List<Ciphertext> combinedCiphertexts = AthenaDistributed.combineCiphertexts(validPfrPhaseOne, pk.group);

        // Phase II: Filter re-votes
        // Verify decryption of homomorphic combination, then Combine shares
        PfPhase<DecryptionShareAndProof> validPfrPhaseTwo = vbb.retrieveValidThresholdPfrPhaseTwo(combinedCiphertexts).join();
        List<BigInteger> noncedNegatedPrivateCredentials = AthenaDistributed.combineDecryptionSharesAndDecrypt(combinedCiphertexts, validPfrPhaseTwo, pk.group);


        // MapA
        Map<MapAKey, MapAValue> A = AthenaTally.performMapA(validBallots, noncedNegatedPrivateCredentials, pk.group);

        // Mixnet: Verify that filtering of ballots(only keeping highest counter) and mixnet is valid
        // Cast to mix ballot list
        List<MixBallot> initialMixBallots = A.values().stream()
                .map(MapAValue::toMixBallot)
                .collect(Collectors.toList());

        // Phase III: Mixnet
        // Map<tallyIndex, MixProof>
        Map<Integer, CompletableFuture<MixedBallotsAndProof>> pfrPhaseThreeMixnet = vbb.retrieveValidMixedBallotAndProofs(initialMixBallots);
        List<MixBallot> finalMixedBallots = pfrPhaseThreeMixnet.get(bb.retrieveTallierCount()).join().mixedBallots; // Could be replaced with a PfPhaseMixnet.getFinalMix()


        /* ********
         * Verify step 3: check the tally revelation
         * This is Phase1, Phase2 and Phase3 for PFD.
         *********/

        // For phase I
        List<Ciphertext> combinedCredentials = finalMixedBallots
                .stream()
                .map(MixBallot::getCombinedCredential)
                .collect(Collectors.toList());

        // For phase III
        List<Ciphertext> encryptedVotes = finalMixedBallots
                .stream()
                .map(MixBallot::getEncryptedVote)
                .collect(Collectors.toList());


        // Phase I. Nonce combinedCredential
        PfPhase<CombinedCiphertextAndProof> validPfdPhaseOne = vbb.retrieveValidThresholdPfdPhaseOne(combinedCredentials).join();
        List<Ciphertext> noncedCombinedCredentials = AthenaDistributed.combineCiphertexts(validPfdPhaseOne, pk.group);

        // Phase II. Decrypt nonced combinedCredential
        PfPhase<DecryptionShareAndProof> validPfdPhaseTwo = vbb.retrieveValidThresholdPfdPhaseTwo(noncedCombinedCredentials).join();
        List<BigInteger> m_list = AthenaDistributed.combineDecryptionSharesAndDecrypt(combinedCredentials, validPfdPhaseTwo, pk.group);

        // Remove unauthorized ballots
        List<Ciphertext> authorizedEncryptedVotes = AthenaDistributed.removeUnauthorizedVotes(m_list, encryptedVotes);

        // Phase III. Decrypt authorized votes
        PfPhase<DecryptionShareAndProof> validPfdPhaseThree = vbb.retrieveValidThresholdPfdPhaseThree(authorizedEncryptedVotes).join();
        List<BigInteger> voteElements = AthenaDistributed.combineDecryptionSharesAndDecrypt(authorizedEncryptedVotes, validPfdPhaseThree, pk.group);

        // Compute tally
        return AthenaTally.computeTally(voteElements, nc, pk.group);
    }

    // Verify that g,h vectors are choosen from a "random" seed.
    private boolean verifyRangeProofGenerators(ElGamalPK pk){
        List<List<BigInteger>> generators = GENERATOR.generateRangeProofGenerators(pk, this.bb.retrieveNumberOfCandidates());
        List<BigInteger> g_vector_vote = generators.get(0);
        List<BigInteger> h_vector_vote = generators.get(1);

        // Verify all 2 vectors
        Pair<List<BigInteger>, List<BigInteger>> g_and_h_vectors = vbb.retrieve_G_and_H_VectorVote();
        List<BigInteger> g_vector_vote_from_bb = g_and_h_vectors.getLeft();
        List<BigInteger> h_vector_vote_from_bb = g_and_h_vectors.getRight();

        boolean isValid1 = g_vector_vote.equals(g_vector_vote_from_bb);
        boolean isValid2 = h_vector_vote.equals(h_vector_vote_from_bb);

        return isValid1 && isValid2;
    }


    public static class Builder {
        private AthenaFactory factory;
//        private Integer kappa;
        
        public Builder setFactory(AthenaFactory factory) {
            this.factory = factory;
            return this;
        }

//        public Builder setKappa(Integer kappa) {
//            this.kappa = kappa;
//            return this;
//        }

        public AthenaVerify build() {
            //Check that all fields are set
            if (
                    factory == null
//                            ||                             kappa == null
            ) {
                throw new IllegalArgumentException("AthenaVerify.Builder: Not all fields have been set");
            }

            AthenaVerify athenaVerify = new AthenaVerify();
            athenaVerify.bb = this.factory.getBulletinBoard();
            athenaVerify.vbb = this.factory.getVerifyingBulletinBoard();

            //Construct Object
            return athenaVerify;
        }
    }
}
