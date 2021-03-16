package project.athena;

import project.CONSTANTS;
import project.dao.athena.*;
import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixProof;
import project.dao.mixnet.MixStatement;
import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma3.Sigma3Statement;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamalPK;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class AthenaVerify {
    private static final int kappa = CONSTANTS.KAPPA;

    private final Sigma1 sigma1;
    private final Bulletproof bulletproof;
    private final Sigma3 sigma3;
    private final Sigma4 sigma4;
    private final Mixnet mixnet;
    private final BulletinBoard bb;
    private BigInteger mc;

    private AthenaVerify(Sigma1 sigma1,
                         Bulletproof bulletproof,
                         Sigma3 sigma3,
                         Sigma4 sigma4,
                         Mixnet mixnet,
                         BulletinBoard bb,
                         BigInteger mc) {

        this.sigma1 = sigma1;
        this.bulletproof = bulletproof;
        this.sigma3 = sigma3;
        this.sigma4 = sigma4;
        this.mixnet = mixnet;
        this.bb = bb;
        this.mc = mc;
    }


    public boolean Verify(PK_Vector pkv,
                          int nc,
                          Map<BigInteger, Integer> tallyOfVotes,
                          PFStruct pf) {
        if (!AthenaCommon.parsePKV(pkv)) {
            System.err.println("AthenaImpl.Verify => ERROR: pkv null");
            return false;
        }
        ElGamalPK pk = pkv.pk;

        // tallyVotes length should contain at most nc elements
        if (tallyOfVotes.keySet().size() > nc) {
            System.err.println("AthenaImpl.Verify => ERROR: tallyOfVotes.keySet().size()=" + tallyOfVotes.keySet().size() + " > nc=" + nc);
            return false;
        }

        // Verify that the ElGamal keys are constructed correctly
        if (!AthenaCommon.verifyKey(sigma1, pkv, kappa)) {
            System.err.println("AthenaImpl.Verify => ERROR: VerifyKey(...) => false");
            return false;
        }

        // Check that the number of candidates nc in the given election does not exceed the maximum number mc.
        if (BigInteger.valueOf(nc).compareTo(this.mc) > 0) { // if nc > mc
            System.err.println("AthenaImpl.Verify => ERROR: nc= " + nc + " > mc=" + mc);
            return false;
        }


        /* ********
         * Check 1: Check ballot removal
         *********/
        // check {b_1,...,b_\ell} = Ø implies b is a zero-filled vector.
        List<Ballot> validBallots = AthenaTally.removeInvalidBallots(pk, bb);
        if (validBallots.isEmpty() && !AthenaCommon.valuesAreAllX(tallyOfVotes, 0)) {
            System.err.println("AthenaImpl.Verify => Check 1 failed.");
            return false;
        }

        /* ********
         * Check 2: Check mix
         *********/
        if (!AthenaCommon.parsePF(pf)) {
            System.err.println("AthenaImpl.Verify => ERROR: pf parsed as null");
            return false;
        }

        // Verify decryption of homomorphic combination
        boolean homoCombinationsAreValid = this.verifyDecryptionOfNoncedPublicCredential(validBallots, pf.pfr, pk);
        if (!homoCombinationsAreValid) {
            return false;
        }

        // Verify that homomorphic combinatins use the same nonce for all negated credentials
        boolean decryptionsAreValid = this.verifySameNonceWasUsedOnAllPublicCredentials(validBallots, pf.pfr, pk);
        if (!decryptionsAreValid) {
            return false;
        }


        // Verify that filtering of ballots(only keeping highest counter) and mixnet is valid
        boolean mixIsValid = checkMix(mixnet, validBallots, pf, pk);
        if (!mixIsValid) {
            return false;
        }

        /* ********
         * Check 3: Check revelation
         *********/
        // Verify that
        return this.checkRevelation(pf.mixBallotList, pf.pfd, pk);
    }

    private static boolean checkMix(Mixnet mixnet, List<Ballot> validBallots, PFStruct pf, ElGamalPK pk) {
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
            MapAValue updatedValue = AthenaTally.getHighestCounterEntry(existingValue, ballot, pk.group.p);
            A.put(key, updatedValue);
        }

        // Cast A map values to list. The result will be an intermediate list of mixBallot b efore mixing.
        List<MixBallot> filteredBallots = A.values()
                .parallelStream()
                .map(MapAValue::toMixBallot)
                .collect(Collectors.toList());

        // Verify mixnet
        MixStatement statement = new MixStatement(filteredBallots, B);
        boolean veri_mix = mixnet.verify(statement, mixProof, kappa);
        if (!veri_mix) {
            System.err.println("AthenaImpl.Verify => ERROR: mixProof was invalid");
            return false;
        }

        return true;
    }

    private boolean verifyDecryptionOfNoncedPublicCredential(List<Ballot> validBallots, List<PFRStruct> pfr, ElGamalPK pk) {
        int ell = validBallots.size();
        // Verify decryption of nonced public credential
        //////////////////////////////////////////////////////////////////////////////////
        // AND_{1<= i <= \ell} sigma3.VerDec(pk, c'[i],N[i] , proveDecryptionOfCombination, \kappa);
        //////////////////////////////////////////////////////////////////////////////////
        for (int i = 0; i < ell; i++) {
            PFRStruct pfr_data = pfr.get(i);
            Ciphertext ci_prime = pfr_data.ciphertextCombination;

//            System.err.println(i + ": AthenaImpl.Verify => ci_prime:");
//            System.err.println(ci_prime.toFormattedString());

            BigInteger noncedNegatedPrivateCredentialElement = pfr_data.plaintext_N;
            Sigma3Proof decyptionProof = pfr_data.proofDecryption;


            /*
             * log_{alpha_base} alpha = log_{beta_base} beta
             *      alpha_base  = g
             *      alpha       = c1^n = Enc_pk(-d)^n mod p = (g^r,g^-d * h^r)^n = (g^{r * n},g^{-d * n} * h^{r * n})
             *      beta_base   = g
             *      beta        = Ni = Dec_sk(ci_prime) = Dec_sk(homoComb(c1,n))= Dec_sk(c1^n mod p)
             *
             * log_{g} c1^n = log_{g} Ni
             */


            // Proove that the nonced private credential was decrypted correctly
            boolean veri_dec = sigma3.verifyDecryption(ci_prime, noncedNegatedPrivateCredentialElement, pk, decyptionProof, kappa);
            if (!veri_dec) {
                System.err.println(i + ": AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption");
//                System.out.println(i + ": ci_prime = " + ci_prime.toFormattedString());
                System.out.println(i + ": Ni       = " + noncedNegatedPrivateCredentialElement);
//                System.out.println(i + ": sigma_i  = " + sigma_i);
                return false;
            }
        }

        return true;
    }

// Verify that the same nonce was used in all noncedPublicCredentials aka. c'
private boolean verifySameNonceWasUsedOnAllPublicCredentials(List<Ballot> validBallots, List<PFRStruct> pfr, ElGamalPK pk) {
        int ell = validBallots.size();
        // Verify that the same nonce was used on all nonced private credentials
        //////////////////////////////////////////////////////////////////////////////////
        // AND_{1< i <= \ell} VerComb(pk, c'[i-1],c'[i] , b_{i-1}[2], b_{i}[2], omega[i], \kappa);
        //////////////////////////////////////////////////////////////////////////////////
        for (int i = 1; i < ell; i++) { // index starts from 1.
            Ciphertext ci_1_prime = pfr.get(i - 1).ciphertextCombination; // the previous combined ballot!
            Ciphertext ci_prime = pfr.get(i).ciphertextCombination;
            Sigma4Proof proofCombination = pfr.get(i).proofCombination;
            Ballot previousBallot = validBallots.get(i - 1); // the previous ballot!
            Ballot currentBallot = validBallots.get(i);

            List<Ciphertext> combinedList = Arrays.asList(ci_1_prime, ci_prime);
            List<Ciphertext> listOfEncryptedNegatedPrivateCredential = Arrays.asList(previousBallot.getEncryptedNegatedPrivateCredential(), currentBallot.getEncryptedNegatedPrivateCredential());

            boolean veri_comb = sigma4.verifyCombination(pk, combinedList, listOfEncryptedNegatedPrivateCredential, proofCombination, kappa);
            if (!veri_comb) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma4.verifyCombination([c'_i-1, c'_i], [b_i-1, b_i])");
                return false;
            }
        }
        return true;
    }

    private boolean checkRevelation(List<MixBallot> B, List<PFDStruct> pfd, ElGamalPK pk) {
        if (pfd.size() != B.size()) {
            System.err.println("AthenaImpl.Verify => ERROR: pfd.size() != |B|");
            return false;
        }

        // Verify that all valid ballots were counted, and that the rest are invalid.
        // [0,1,..., |B|-1]
        List<Integer> uncountedBallotIndices = IntStream
                .rangeClosed(0, B.size() - 1).boxed()
                .collect(Collectors.toList());

        // Find which ballots vote for each candidate
        // [0, .... |B| -1]  = [0, 100]
        Map<BigInteger, Integer> tally = new HashMap<>();
        List<Integer> countedBallotIndices = new ArrayList<>();


        // Find and count valid ballots
        for (Integer i : uncountedBallotIndices) {
            // Get relevant data
            MixBallot mixBallot = B.get(i);
            Ciphertext combinedCredential = mixBallot.getC1();
            Ciphertext encryptedVote = mixBallot.getC2();

            PFDStruct verificationInfo = pfd.get(i);
            Ciphertext c_prime = verificationInfo.ciphertextCombination;
            Sigma4Proof proofCombination = verificationInfo.proofCombination;

            // Verify homo combination
            boolean veri_comb = sigma4.verifyCombination(pk, c_prime, combinedCredential, proofCombination, kappa);
            if (!veri_comb) {
                System.out.println(i + "AthenaImpl.Verify => ERROR: Sigma4.verifyCombination(c', c1)");
                continue;
            }

            // Verify decryption of homo combitation into plaintext "1"
            Sigma3Proof proofDecryptionOfCombination = verificationInfo.proofDecryptionOfCombination;
            boolean veri_dec_1 = sigma3.verifyDecryption(c_prime, BigInteger.ONE, pk, proofDecryptionOfCombination, kappa);
            if (!veri_dec_1) {
                System.out.println(i + "AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption(c', 1)");
                continue;
            }

            // Verify decryption of vote
            BigInteger vote = verificationInfo.plaintext;
            Sigma3Proof proofDecryptionVote = verificationInfo.proofDecryptionVote;
            boolean veri_dec_v = sigma3.verifyDecryption(encryptedVote, vote, pk, proofDecryptionVote, kappa);
            if (!veri_dec_v) {
                System.out.println(i + "AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption(encryptedVote, vote)");
                continue;
            }

            // All checks succeeded. Increment tally and remember "good candidates"
            // https://stackoverflow.com/a/42648785
            tally.merge(vote, 1, Integer::sum);
            countedBallotIndices.add(i);

            // Ensure that the tallier counted ALL valid ballots.
            if (tally.get(vote) > countedBallotIndices.get(vote.intValueExact())) {
                System.out.println("AthenaImpl.Verify. Tallier did not count all valid votes");
                return false;
            }
        }

        // Remove the indices from 'countedBallotIndices' from 'uncountedBallotIndices'
        uncountedBallotIndices.removeAll(countedBallotIndices);

        // and for each remaining integer i \in {1,..., |B|}
        for (int j : uncountedBallotIndices) {
            // "else case" in the verification step 3
            MixBallot mixBallot = B.get(j);
            Ciphertext combinedCredential = mixBallot.getC1();

            PFDStruct pfd_data = pfd.get(j);
            Ciphertext c_prime = pfd_data.ciphertextCombination;
            Sigma4Proof proofCombination = pfd_data.proofCombination;

            // Verify homo combination
            boolean veri_comb = sigma4.verifyCombination(
                    pk,
                    Collections.singletonList(c_prime),
                    Collections.singletonList(combinedCredential),
                    proofCombination,
                    kappa);
            if (!veri_comb) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma4.verifyCombination(c', c1)");
                return false;
            }

            // Verify decryption of homo combination into m != 1
            BigInteger m = pfd_data.plaintext;
            Sigma3Proof proofDecryptionOfCombination = pfd_data.proofDecryptionOfCombination;
            boolean veri_dec_m = sigma3.verifyDecryption(c_prime, m, pk, proofDecryptionOfCombination, kappa);
            if (!veri_dec_m) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption(c', m)");
                return false;
            }

            if (!m.equals(BigInteger.ONE)) {
                System.err.println("AthenaImpl.Verify => ERROR: m == 1");
                return false;
            }
        }

        return true;
    }


    public static class Builder {
        private Sigma1 sigma1;
        private Bulletproof bulletproof;
        private Sigma3 sigma3;
        private Sigma4 sigma4;
        private Mixnet mixnet;
        private BulletinBoard bb;
        private BigInteger mc;

        public Builder setSigma1(Sigma1 sigma1) {
            this.sigma1 = sigma1;
            return this;
        }


        public Builder setBulletproof(Bulletproof bulletproof) {
            this.bulletproof = bulletproof;
            return this;
        }

        public Builder setSigma3(Sigma3 sigma3) {
            this.sigma3 = sigma3;
            return this;
        }

        public Builder setSigma4(Sigma4 sigma4) {
            this.sigma4 = sigma4;
            return this;
        }

        public Builder setMixnet(Mixnet mixnet) {
            this.mixnet = mixnet;
            return this;
        }


        public Builder setBB(BulletinBoard bb) {
            this.bb = bb;
            return this;
        }

        public Builder setMc(BigInteger mc) {
            this.mc = mc;
            return this;
        }

        public AthenaVerify build() {
            //Check that all fields are set
            if (
                    sigma1 == null ||
                            bulletproof == null ||
                            sigma3 == null ||
                            sigma4 == null ||
                            mixnet == null ||
                            bb == null
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            return new AthenaVerify(sigma1, bulletproof, sigma3, sigma4, mixnet, bb, mc);
        }


    }
}
