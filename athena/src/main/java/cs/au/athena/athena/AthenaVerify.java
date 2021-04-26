package cs.au.athena.athena;

import cs.au.athena.GENERATOR;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.VerifyingBulletinBoardV2_0;
import cs.au.athena.athena.distributed.AthenaDistributed;
import cs.au.athena.dao.athena.*;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.factory.AthenaFactory;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class AthenaVerify {
    private AthenaDistributed distributed;
    private BulletinBoardV2_0 bb;
    private VerifyingBulletinBoardV2_0 vbb;
    private Integer kappa;

    private AthenaVerify() {
    }


    public boolean Verify() {
        //Fetch from bulletin board
        int nc = this.bb.retrieveNumberOfCandidates();
        Map<Integer, Integer> tallyOfVotes = this.bb.retrieveTallyOfVotes();
        PFStruct pf = this.bb.retrievePF(); // TODO: retrieve this another way! Should be done through the verifying bulleting board

        // tallyVotes length should contain at most nc elements
        if (tallyOfVotes.keySet().size() > nc) {
            System.err.println("AthenaVerify:=> ERROR: tallyOfVotes.keySet().size()=" + tallyOfVotes.keySet().size() + " > nc=" + nc);
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
        boolean isValid = verifyRangeProofGenerators(pk, this.bb, this.vbb);
        if(!isValid) {
            System.out.println("AthenaTally.removeInvalidBallots: error");
        }


        /* ********
         * Check 1: Check ballot removal
         *********/
        // check {b_1,...,b_\ell} = Ø implies b is a zero-filled vector.
        List<Ballot> validBallots = AthenaTally.removeInvalidBallots(pk, this.bb, this.vbb);
        if (validBallots.isEmpty() && !AthenaCommon.valuesAreAllX(tallyOfVotes, 0)) {
            System.err.println("AthenaVerify:=> Check 1 failed.");
            return false;
        }

        /* ********
         * Check 2: Check mix
         *********/
        if (!AthenaCommon.parsePF(pf)) {
            System.err.println("AthenaVerify:=> ERROR: pf parsed as null");
            return false;
        }

        // Verify decryption of homomorphic combination
        boolean homoCombinationsAreValid = this.verifyDecryptionOfNoncedNegatedPrivateCredential(validBallots, pf.pfr, pk);
        if (!homoCombinationsAreValid) {
            return false;
        }

        // Verify that homomorphic combinatins use the same nonce for all negated credentials
        boolean decryptionsAreValid = this.verifySameNonceWasUsedOnAllPublicCredentials(validBallots, pf.pfr, pk);
        if (!decryptionsAreValid) {
            return false;
        }


        // Verify that filtering of ballots(only keeping highest counter) and cs.au.cs.au.athena.athena.mixnet is valid
        boolean mixIsValid = checkMix(distributed, validBallots, pf, pk, this.kappa);
        if (!mixIsValid) {
            return false;
        }

        /* ********
         * Check 3: Check revelation
         *********/
        // Verify that
        return this.checkRevelation(pf.mixBallotList, pf.pfd, tallyOfVotes, pk, nc);
    }

    // Verify that g,h vectors are choosen from a "random" seed.
    private boolean verifyRangeProofGenerators(ElGamalPK pk, BulletinBoardV2_0 bb){
        List<List<BigInteger>> generators = GENERATOR.generateRangeProofGenerators(pk, bb.retrieveNumberOfCandidates());
        List<BigInteger> g_vector_vote = generators.get(0);
        List<BigInteger> h_vector_vote = generators.get(1);

        // Verify all 2 vectors
        boolean isValid1 = g_vector_vote.equals(vbb.retrieve_G_VectorVote());
        boolean isValid2 = h_vector_vote.equals(vbb.retrieve_H_VectorVote());

        return isValid1 && isValid2;
    }

    private static boolean checkMix(AthenaDistributed distributed, List<Ballot> validBallots, PFStruct pf, ElGamalPK pk, int kappa) {
        int ell = validBallots.size();
        List<PFRStruct> pfr = pf.pfr;
        List<MixBallot> B = pf.mixBallotList;
        MixProof mixProof = pf.mixProof;

        // initialise A as an empty map from pairs to triples, then filter
        Map<MapAKey, MapAValue> A = new HashMap<>();
        for (int i = 0; i < ell; i++) {
            Ballot ballot = validBallots.get(i);
            BigInteger N = pfr.get(i).plaintext_N;

            // Update the map with ballots. ballots t <- A.get(key_i)
            // Update the map entry if the old counter is less. Nullify if equal
            MapAKey key = new MapAKey(ballot.getPublicCredential(), N);
            MapAValue existingValue = A.get(key);
            MapAValue updatedValue = AthenaTally.getHighestCounterEntry(existingValue, ballot, pk.group);
            A.put(key, updatedValue);
        }

        // Cast A map values to list. The result will be an intermediate list of mixBallot b efore mixing.
        List<MixBallot> filteredBallots = A.values()
                .parallelStream()
                .map(MapAValue::toMixBallot)
                .collect(Collectors.toList());

        // TODO: Verify strategy
        // Verify mixnet
        MixStatement statement = new MixStatement(filteredBallots, B);
        boolean veri_mix = distributed.verifyMix(statement, mixProof, pk, kappa);
        if (!veri_mix) {
            System.err.println("AthenaVerify:=> ERROR: mixProof was invalid");
            return false;
        }

        return true;
    }

    private boolean verifyDecryptionOfNoncedNegatedPrivateCredential(List<Ballot> validBallots, List<PFRStruct> pfr, ElGamalPK pk) {
        int ell = validBallots.size();
        // Verify decryption of nonced public credential
        for (int i = 0; i < ell; i++) {
            PFRStruct pfr_data = pfr.get(i);

            // Prove that the nonced private credential was decrypted correctly
            boolean veri_dec = this.distributed.verifyDecryption(pfr_data.ciphertextCombination, pfr_data.plaintext_N, pk, pfr_data.proofDecryption, kappa);
            if (!veri_dec) {
                System.err.println(i + ": AthenaVerify:=> ERROR: Sigma3.verifyDecryption");
                return false;
            }
        }

        return true;
    }

    // Verify that the same nonce was used in all noncedPublicCredentials aka. c'
    private boolean verifySameNonceWasUsedOnAllPublicCredentials(List<Ballot> validBallots, List<PFRStruct> pfr, ElGamalPK pk) {
        int ell = validBallots.size();
        // Verify that the same nonce was used on all nonced private credentials
        for (int i = 1; i < ell; i++) { // index starts from 1.
            Ciphertext ci_1_prime = pfr.get(i - 1).ciphertextCombination; // the previous combined ballot!
            Ciphertext ci_prime = pfr.get(i).ciphertextCombination;
            Sigma4Proof proofCombination = pfr.get(i).proofCombination;
            Ballot previousBallot = validBallots.get(i - 1); // the previous ballot!
            Ballot currentBallot = validBallots.get(i);
            List<Ciphertext> combinedList = Arrays.asList(ci_1_prime, ci_prime);
            List<Ciphertext> listOfEncryptedNegatedPrivateCredential = Arrays.asList(previousBallot.getEncryptedNegatedPrivateCredential(), currentBallot.getEncryptedNegatedPrivateCredential());

            boolean veri_comb = this.distributed.verifyCombination(combinedList, listOfEncryptedNegatedPrivateCredential, proofCombination, pk, kappa);
            if (!veri_comb) {
                System.err.println("AthenaVerify:=> ERROR: Sigma4.verifyCombination([c'_i-1, c'_i], [b_i-1, b_i])");
                return false;
            }
        }
        return true;
    }

    private boolean checkRevelation(List<MixBallot> B, List<PFDStruct> pfd, Map<Integer, Integer> officialTally, ElGamalPK pk, int nc) {
        if (pfd.size() != B.size()) {
            System.err.println("AthenaVerify:=> ERROR: pfd.size() != |B|");
            return false;
        }

        BigInteger p = pk.getGroup().getP();
        BigInteger g = pk.getGroup().getG();

        // Verify that all valid ballots were counted, and that the rest are invalid.
        List<Integer> uncountedBallotIndices = IntStream
                .rangeClosed(0, B.size() - 1).boxed()
                .collect(Collectors.toList());

        // Find which ballots vote for each candidate
        Map<Integer, Integer> tally = new HashMap<>(nc);
        for (int candidate = 0; candidate < nc; candidate++) {
            tally.put(candidate, 0);
        }

        List<Integer> countedBallotIndices = new ArrayList<>();
        // Find and count valid ballots
        for (Integer i : uncountedBallotIndices) {
            // Get relevant data
            MixBallot mixBallot = B.get(i);
            Ciphertext combinedCredential = mixBallot.getCombinedCredential();
            Ciphertext encryptedVote = mixBallot.getEncryptedVote();

            PFDStruct verificationInfo = pfd.get(i);
            Ciphertext c_prime = verificationInfo.ciphertextCombination;
            Sigma4Proof proofCombination = verificationInfo.proofCombination;

            // Verify homo combination
            boolean veri_comb = this.distributed.verifyCombination(Collections.singletonList(c_prime), Collections.singletonList(combinedCredential), proofCombination, pk, kappa);
            if (!veri_comb) {
                System.out.println(i + ": AthenaVerify:=> ERROR: Sigma4.verifyCombination(c', c1)");
                continue;
            }

            // Verify decryption of homo combitation into plaintext "1"
            boolean veri_dec_1 = this.distributed.verifyDecryption(c_prime, BigInteger.ONE, pk, verificationInfo.proofDecryptionOfCombination, kappa);
            if (!veri_dec_1) {
                System.out.println(i + ": AthenaVerify:=> Caught wrong ballot in: Sigma3.verifyDecryption(c', 1). Skipping ballot");
                continue;
            }

            // Verify decryption of vote
            BigInteger voteElement = verificationInfo.plaintext;
            boolean veri_dec_v = this.distributed.verifyDecryption(encryptedVote, voteElement, pk, verificationInfo.proofDecryptionVote, kappa);
            if (!veri_dec_v) {
                System.out.println(i + " AthenaVerify:=> ERROR: Sigma3.verifyDecryption(encryptedVote, vote)");
                continue;
            }

            // All checks succeeded. Increment tally and remember "good candidates"
            int vote = Elgamal.lookup(Elgamal.generateLookupTable(pk.group, nc),voteElement);

            // https://stackoverflow.com/a/42648785
            tally.merge(vote, 1, Integer::sum);
            countedBallotIndices.add(i);
        }

        // Check that our tally matches talliers tally
        for (int candidate = 0; candidate < nc; candidate++) {

            if (!tally.get(candidate).equals(officialTally.get(candidate))) {
                System.err.println(candidate + ": AthenaVerify: Tallier did not count valid votes correctly");
                System.out.println(candidate + ": tally.get(candidate)        =" + tally.get(candidate));
                System.out.println(candidate + ": officialTally.get(candidate)=" + officialTally.get(candidate));
                return false;
            }
        }


        // Remove the indices from 'countedBallotIndices' from 'uncountedBallotIndices'
        uncountedBallotIndices.removeAll(countedBallotIndices);

        // and for each remaining integer i \in {1,..., |B|}
        for (int j : uncountedBallotIndices) {
            // "else case" in the verification step 3
            MixBallot mixBallot = B.get(j);
            Ciphertext combinedCredential = mixBallot.getCombinedCredential();

            PFDStruct pfd_data = pfd.get(j);
            Ciphertext c_prime = pfd_data.ciphertextCombination;
            Sigma4Proof proofCombination = pfd_data.proofCombination;

            // Verify homo combination
            boolean veri_comb = this.distributed.verifyCombination(
                    Collections.singletonList(c_prime),
                    Collections.singletonList(combinedCredential),
                    proofCombination,
                    pk,
                    kappa);
            if (!veri_comb) {
                System.err.println(j + ": AthenaVerify:=> ERROR: Sigma4.verifyCombination(c', c1)");
                return false;
            }

            // Verify decryption of homo combination into m != 1
            BigInteger m = pfd_data.plaintext;
            Sigma3Proof proofDecryptionOfCombination = pfd_data.proofDecryptionOfCombination;
            boolean veri_dec_m = this.distributed.verifyDecryption(c_prime, m, pk, proofDecryptionOfCombination, kappa);
            if (!veri_dec_m) {
                System.err.println(j + ": AthenaVerify:=> ERROR: Sigma3.verifyDecryption(c', m)");
                return false;
            }

            // if m != 1 then output false
            if (m.equals(BigInteger.ONE)) {
                System.err.println(j + ": AthenaVerify:=> ERROR: m == 1");
                return false;
            }
        }

        return true;
    }


    public static class Builder {
        private AthenaFactory factory;
        private Integer kappa;
        
        public Builder setFactory(AthenaFactory factory) {
            this.factory = factory;
            return this;
        }

        public Builder setKappa(Integer kappa) {
            this.kappa = kappa;
            return this;
        }

        public AthenaVerify build() {
            //Check that all fields are set
            if (
                    factory == null ||
                            kappa == null
            ) {
                throw new IllegalArgumentException("AthenaVerify.Builder: Not all fields have been set");
            }

            AthenaVerify athenaVerify = new AthenaVerify();
            athenaVerify.distributed = this.factory.getDistributedAthena();
            athenaVerify.bb = this.factory.getBulletinBoard();
            athenaVerify.vbb = this.factory.getVerifyingBulletinBoard();
            athenaVerify.kappa = this.kappa;

            //Construct Object
            return athenaVerify;
        }


    }
}
