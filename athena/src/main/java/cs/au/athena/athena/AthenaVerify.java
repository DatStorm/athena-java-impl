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
        Map<Integer, Map<Integer, Integer>> officialTallys = this.bb.retrieveOfficialTally();

        // tallyVotes length should contain at most nc elements
        if (officialTally.keySet().size() > nc) {
            System.err.println("AthenaVerify:=> ERROR: tallyOfVotes.keySet().size()=" + officialTally.keySet().size() + " > nc=" + nc);
            return false;
        }

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


        /* ********
         * Verify Step 1: check ballot removal
         *********/
        List<Ballot> validBallots = AthenaTally.removeInvalidBallots(pk, this.bb, this.vbb);
        if (validBallots.isEmpty() && !AthenaCommon.valuesAreAllX(officialTally, 0)) {
            System.err.println("AthenaVerify:=> Check 1 failed.");
            return false;
        }


        /* ********
         * Verify step 2: check mixing
         *********/
        List<Ciphertext> encryptedNegatedPrivateCredentials = validBallots
                .stream()
                .map(Ballot::getEncryptedNegatedPrivateCredential)
                .collect(Collectors.toList());

        // Verify homo comb proofs, and get nonced negated private credentials
        // Combine shares
        PfPhase<CombinedCiphertextAndProof> validPfrPhaseOne = vbb.retrieveValidThresholdPfrPhaseOne(encryptedNegatedPrivateCredentials).join();
        List<Ciphertext> combinedCiphertexts = AthenaDistributed.combineCiphertexts(validPfrPhaseOne, pk.group);


        // Verify decryption of homomorphic combination
        // Combine shares
        PfPhase<DecryptionShareAndProof> validPfrPhaseTwo = vbb.retrieveValidThresholdPfrPhaseTwo(combinedCiphertexts).join();
        List<BigInteger> noncedNegatedPrivateCredentials = AthenaDistributed.combineDecryptionSharesAndDecrypt(combinedCiphertexts, validPfrPhaseTwo, pk.group);


        // MapA
        Map<MapAKey, MapAValue> A = AthenaTally.performMapA(validBallots, noncedNegatedPrivateCredentials, pk.group);

        // Mixnet: Verify that filtering of ballots(only keeping highest counter) and mixnet is valid
        // Cast to mix ballot list
        List<MixBallot> initialMixBallots = A.values().stream()
                .map(MapAValue::toMixBallot)
                .collect(Collectors.toList());

        // Map<tallyIndex, MixProof>
        Map<Integer, CompletableFuture<MixedBallotsAndProof>> pfrPhaseThreeMixnet = vbb.retrieveValidMixedBallotAndProofs(initialMixBallots);
        List<MixBallot> finalMixedBallots = pfrPhaseThreeMixnet.get(bb.retrieveTallierCount()).join().mixedBallots; // Could be replaced with a PfPhaseMixnet.getFinalMix()



        /* ********
         * Verify step 3: check the tally revelation
         * This is Phase1, Phase2 and Phase3 for PFD.
         *********/

        //checkrevalation udregner tally. og retunere isValid = tally == officialTally.
        //is my "tally" == "oficialTally";

        boolean check = this.checkRevelation(finalMixedBallots, officialTally, pk, nc);
        logger.info(MARKER, "AthenaVerify.Verify[ended]");
        return check;
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


    private boolean checkRevelation(List<MixBallot> mixedBallots, Map<Integer, Integer> officialTally, ElGamalPK pk, int nc) {

        // For phase I
        List<Ciphertext> combinedCredentials = mixedBallots
                .stream()
                .map(MixBallot::getCombinedCredential)
                .collect(Collectors.toList());

        // For phase III
        List<Ciphertext> encryptedVotes = mixedBallots
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
        Map<Integer, Integer> tally = AthenaTally.computeTally(voteElements, nc, pk.group);

        // Verify tally
        return tally.equals(officialTally);
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
