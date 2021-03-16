package project.athena;

import org.apache.commons.lang3.tuple.Pair;
import project.CONSTANTS;
import project.UTIL;
import project.dao.athena.*;
import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixProof;
import project.dao.mixnet.MixStatement;
import project.dao.mixnet.MixStruct;
import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

public class AthenaTally {
    private static final int kappa = CONSTANTS.KAPPA;

    private Random random;
    private ElGamal elgamal;
    private BulletinBoard bb;

    private Sigma1 sigma1;
    private Bulletproof bulletProof;
    private Sigma3 sigma3;
    private Sigma4 sigma4;
    private Mixnet mixnet;

    // Construct using builder
    private AthenaTally() {}

    public TallyStruct Tally(SK_Vector skv, int nc) {

        ElGamalSK sk = skv.sk;
        ElGamalPK pk = sk.pk;
        BigInteger p = pk.getGroup().p;
        BigInteger q = pk.getGroup().q;

        // voter 1 votes  => 7
        // voter 2 votes  => 3
        List<BigInteger> res2 = Arrays.asList(BigInteger.valueOf(7), BigInteger.valueOf(3));
//        System.out.println("-----------------------------------");
//        System.out.println("BB: "+ this.bb.retrievePublicBallots());
//        System.out.println("-----------------------------------");

        int i = 0;
        for (Ballot ballot : this.bb.retrievePublicBallots()) {
            Ciphertext encryptedVote = ballot.getEncryptedVote();
            System.out.println("JA TAK          :::  " + encryptedVote.toFormattedString());
            BigInteger dec = elgamal.decrypt(encryptedVote, sk);
            System.out.println("AthenaTally.Tally Dec_sk(..) = " + dec);
            System.out.println("AthenaTally.Tally res = " + res2.get(i));
            assert dec.equals(res2.get(i)) : "Det fejler....";
            i++;
        }

        /* ********
         * Step 1: Remove invalid ballots
         *********/
        List<Ballot> validBallots = removeInvalidBallots(pk, this.bb);
        if (validBallots.isEmpty()){
            System.err.println("AthenaImpl.Tally =>  Step 1 yielded no valid ballots on bulletinboard.");
            return null;
        }


        /* ********
         * Step 2: Mix final votes
         *********/
        //Filter ReVotes and pfr proof of same nonce
        Pair<Map<MapAKey, MapAValue>, List<PFRStruct>> filterResult = filterReVotesAndProveSameNonce(validBallots, sk);
        Map<MapAKey, MapAValue> A = filterResult.getLeft();
        List<PFRStruct> pfr = filterResult.getRight();

        System.out.println("A: " + A.values().stream()
                .map(MapAValue::getCombinedCredential)
                .map(combinedCredential -> elgamal.decryptWithoutLookup(combinedCredential, sk))
                .collect(Collectors.toList()));

        assert A.values().stream()
                .map(MapAValue::getCombinedCredential)
                .map(combinedCredential -> elgamal.decryptWithoutLookup(combinedCredential, sk))
                .allMatch(decryptedCombinedCredential -> decryptedCombinedCredential.equals(BigInteger.ONE)) : "Not equal 1 before mixing";


        // voter 1 votes  => 7
        // voter 2 votes  => 3
        List<BigInteger> res = Arrays.asList(BigInteger.valueOf(3), BigInteger.valueOf(7));
        int i2 = 0;
        for (MapAValue value : A.values()) {
            BigInteger dec = elgamal.decrypt(value.getEncryptedVote(), sk);
            System.out.println("AthenaTally.Tally Dec_sk(..) = " + dec);
            assert dec.equals(res.get(i2)) : "Det fejler....";
            i2++;
        }







        // Perform random mix
        Pair<List<MixBallot>, MixProof> mixPair = mixnet(A);
        List<MixBallot> mixedBallots = mixPair.getLeft();
        MixProof mixProof = mixPair.getRight();


        for (MixBallot value : mixedBallots) {
            BigInteger dec = elgamal.decrypt(value.getEncryptedVote(), sk);
            System.out.println("AthenaTally.Tally Dec_sk(..) = " + dec);
            assert res.contains(dec) : "Det fejler2....";
        }



        assert mixedBallots.stream()
                .map(MixBallot::getCombinedCredential)
                .map(combCred -> elgamal.decryptWithoutLookup(combCred, sk))
                .allMatch(decryptedCombinedCredential -> decryptedCombinedCredential.equals(BigInteger.ONE)): "Not equal 1 after mixing";

        System.out.println("M: " + mixedBallots.stream()
                .map(MixBallot::getCombinedCredential)
                .map(combCred -> elgamal.decryptWithoutLookup(combCred, sk))
                .collect(Collectors.toList()));

        System.out.println("---> |B|: " + mixedBallots.size());

        /* ********
         * Step 3: Reveal eligible votes
         *********/
        // Tally eligible votes and prove computations
        Pair<Map<BigInteger, Integer>, List<PFDStruct>> revealPair = revealEligibleVotes(sk, mixedBallots, kappa);
        Map<BigInteger, Integer> tallyOfVotes = revealPair.getLeft();
        List<PFDStruct> pfd = revealPair.getRight();

        // Post (b, (pfr, B, pfd) ) to bullitin board
        bb.publishTallyOfVotes(tallyOfVotes);
        PFStruct pf = new PFStruct(pfr, mixedBallots, pfd, mixProof);
        bb.publishPF(pf);

        return new TallyStruct(tallyOfVotes, pf);
    }

    // Step 1 of Tally
    public static List<Ballot> removeInvalidBallots(ElGamalPK pk, BulletinBoard bb) {
        List<Ballot> finalBallots = new ArrayList<>(bb.retrievePublicBallots());

        System.out.println("FINAL BALLOTS.size(): " + finalBallots.size());

        for (Ballot ballot : bb.retrievePublicBallots()) {
            Ciphertext publicCredential = ballot.getPublicCredential();

            // Is the public credential
            boolean isPublicCredentialInL = bb.electoralRollContains(publicCredential);
            if (!isPublicCredentialInL) {
                System.err.println("AthenaImpl.removeInvalidBallot => ballot posted with invalid public credential");
                finalBallots.remove(ballot);
            }

//            // Verify that the negated private credential is in the valid range
//            // ElGamal ciphertext (c1,c2) => use c2=g^(-d) h^s as Pedersens' commitment of (-d) using randomness s
//            CipherText encryptedNegatedPrivateCredential = ballot.getEncryptedNegatedPrivateCredential();
//            BulletproofStatement stmnt_1 = new BulletproofStatement(n_vote, encryptedNegatedPrivateCredential.c2, pk, g_vector_negatedPrivateCredential, h_vector_negatedPrivateCredential);
//            boolean verify_encryptedNegatedPrivateCredential = bulletProof.verifyStatement(stmnt_1, ballot.getProofNegatedPrivateCredential());
//
//
//            // remove invalid ballots.
//            if (!verify_encryptedNegatedPrivateCredential) {
//                finalBallots.remove(ballot);
//            }
//
//            // Verify that the vote is in the valid range
//            // ElGamal ciphertext (c1,c2) => use c2=g^(v) h^t as Pedersens' commitment of vote v using randomness t
//            CipherText encryptedVote = ballot.getEncryptedVote();
//            BulletproofStatement stmnt_2 = new BulletproofStatement(n_negatedPrivateCredential, encryptedVote.c2, pk, g_vector_vote, h_vector_vote);
//            boolean verify_encryptedVote = bulletProof.verifyStatement(stmnt_2, ballot.getProofVote());
//
//            // remove invalid ballots.
//            if (!verify_encryptedVote) {
//                finalBallots.remove(ballot);
//            }
        }

        return finalBallots;
    }

    // Step 2 of Tally. Returns map of the highest counter ballot, for each credential pair, and a proof having used the same nonce for all ballots.
    private Pair<Map<MapAKey, MapAValue>, List<PFRStruct>> filterReVotesAndProveSameNonce(List<Ballot> ballots, ElGamalSK sk) {
        int ell = ballots.size();

        List<PFRStruct> pfr = new ArrayList<>();
        Map<MapAKey, MapAValue> A = new HashMap<>();

        // Pick a nonce to mask public credentials.
        BigInteger nonce_n = UTIL.getRandomElement(sk.pk.group.q, random);

        // For each ballot.
        Ciphertext ci_prime_previous = null;
        for (int i = 0; i < ell; i++) {
            Ballot ballot = ballots.get(i);

            // Homomorpically reencrypt(by raising to power n) ballot and decrypt
            Ciphertext ci_prime = AthenaCommon.homoCombination(ballot.getEncryptedNegatedPrivateCredential(), nonce_n, sk.pk.group.p);

            // Dec(Enc(x)) = Dec((c1,c2)) = Dec((g^r,g^x * h^r)) = g^x
            BigInteger noncedNegatedPrivateCredentialElement = elgamal.decryptWithoutLookup(ci_prime, sk);

            if (i == 0) { // Just for debug help
                System.out.println(i + "--> AthenaTally.filterReVotesAndProveSameNonce Ni: " + noncedNegatedPrivateCredentialElement);
            }

            // Update map with highest counter entry.
            MapAKey key = new MapAKey(ballot.getPublicCredential(), noncedNegatedPrivateCredentialElement);
            MapAValue existingValue = A.get(key);
            MapAValue updatedValue = getHighestCounterEntry(existingValue, ballot, sk.pk.group.p);
            A.put(key, updatedValue);

            // Prove decryption
            Sigma3Proof decryptionProof = sigma3.proveDecryption(ci_prime, noncedNegatedPrivateCredentialElement, sk, kappa);
//            Sigma3Statement stmnt = Sigma3.createStatement(sk.pk, ci_prime, ); //
//            BigInteger secret = null ;
//            Sigma3Proof decryptionProof = sigma3.proveDecryption(stmnt, secret, kappa);

            // Proove that the same nonce was used for all ballots.
            if (pfr.size() > 0) {
                // Prove c0 i−1 and c0 i are derived by iterative homomorphic combination wrt nonce n
                List<Ciphertext> listCombined = Arrays.asList(ci_prime_previous, ci_prime);
                List<Ciphertext> listCiphertexts = Arrays.asList(ballots.get(i - 1).getEncryptedNegatedPrivateCredential(), ballot.getEncryptedNegatedPrivateCredential());
                Sigma4Proof omega = sigma4.proveCombination(sk, listCombined, listCiphertexts, nonce_n, kappa);

                pfr.add(new PFRStruct(ci_prime, noncedNegatedPrivateCredentialElement, decryptionProof, omega));
            } else {
                // The else case does not create the ProveComb since this else case is only used in the first iteration
                // of the loop true case is used the remaining time.
                pfr.add(new PFRStruct(ci_prime, noncedNegatedPrivateCredentialElement, decryptionProof, null));
            }

            ci_prime_previous = ci_prime;
        }

        return Pair.of(A, pfr);
    }

    // Step 2 of Tally. Returns a MapAValue, representing the ballot with the highest counter.
    public static MapAValue getHighestCounterEntry(MapAValue existingValue, Ballot ballot, BigInteger p) {
        // Update the map entry if the old counter is less. Nullify if equal
        int counter = ballot.getCounter();
        if (existingValue == null || existingValue.getCounter() < counter) {
            // Update the map if A[(bi[1]; N)] is empty, or contains a lower counter

            Ciphertext combinedCredential = ballot.getPublicCredential().multiply(ballot.getEncryptedNegatedPrivateCredential(), p);

            System.out.println("AthenaTally.getHighestCounterEntry combCred: " + combinedCredential.toFormattedString());
            MapAValue updatedValue = new MapAValue(counter, combinedCredential, ballot.getEncryptedVote());

            return updatedValue;

        } else if (existingValue.getCounter() == counter) {
            // Duplicate counters are illegal. Set null entry.
            MapAValue nullValue = new MapAValue(counter, null, null);
            return nullValue;

        } else {

            return existingValue;
        }
    }

    // Step 2 of Tally. Mix ballots
    private Pair<List<MixBallot>, MixProof> mixnet(Map<MapAKey, MapAValue> A) {
        // Cast to mix ballot list
        List<MixBallot> ballots = A.values().stream()
                .map(MapAValue::toMixBallot)
                .collect(Collectors.toList());

        // Mix ballots
        MixStruct mixStruct = this.mixnet.mix(ballots);
        List<MixBallot> mixedBallots = mixStruct.mixedBallots;

        // Prove mix
        MixStatement statement = new MixStatement(ballots, mixedBallots);
        MixProof mixProof = mixnet.proveMix(statement, mixStruct.secret, kappa);
        assert mixnet.verify(statement, mixProof, kappa);

        return Pair.of(mixedBallots, mixProof);
    }

    // Step 3 of tally. Nonce and decrypt ballots, and keep a tally of the eligible votes.
    private Pair<Map<BigInteger, Integer>, List<PFDStruct>> revealEligibleVotes(ElGamalSK sk, List<MixBallot> mixedBallots, int kappa) {
        Map<BigInteger, Integer> tallyOfVotes = new HashMap<>();
        List<PFDStruct> pfd = new ArrayList<>(mixedBallots.size());

        BigInteger p = sk.pk.group.p;
        BigInteger q = sk.pk.group.q;

        for (MixBallot mixBallot : mixedBallots) {
            Ciphertext combinedCredential = mixBallot.getCombinedCredential();
            Ciphertext encryptedVote = mixBallot.getEncryptedVote();

            // Apply a nonce to the combinedCredential
            BigInteger nonce = UTIL.getRandomElement(BigInteger.ONE, q, random);
            Ciphertext c_prime = AthenaCommon.homoCombination(combinedCredential, nonce, p);

            // Decrypt nonced combinedCredential
            BigInteger m_mark = elgamal.decryptWithoutLookup(combinedCredential, sk);
            assert m_mark.equals(BigInteger.ONE) : "Something wrong ??";

            BigInteger m = elgamal.decryptWithoutLookup(c_prime, sk);
            System.out.println("--> c_prime: " +  c_prime);
            System.out.println("--> m:       " +  m);


            // Prove that c' is a homomorphic combination of combinedCredential
            Sigma4Proof combinationProof = sigma4.proveCombination(
                    sk,
                    c_prime,
                    combinedCredential,
                    nonce,
                    kappa);

            // Prove that msg m is the correct decryption of c'
            Sigma3Proof combinationDecryptionProof = sigma3.proveDecryption(c_prime, m, sk, kappa);

            // Check validity of private credential. (decrypted combinedCredential = 1)
            if (m.equals(BigInteger.ONE)) {
                System.out.println("AthenaTally.revealEligibleVotes CASE: M=1  ");
                System.out.println("AthenaTally.revealEligibleVotes Enc_pk(v): " + encryptedVote.toFormattedString());

                // Decrypt vote
                BigInteger vote = elgamal.decrypt(encryptedVote, sk);

                // Tally the vote
                if (tallyOfVotes.containsKey(vote)) { // Check that map already has some votes for that candidate.
                    Integer totalVotes = tallyOfVotes.get(vote);
                    tallyOfVotes.put(vote, totalVotes + 1);
                } else { // First vote for the given candidate
                    tallyOfVotes.put(vote, 1);
                }

                // Prove correct decryption of vote
                Sigma3Proof voteDecryptionProof = sigma3.proveDecryption(encryptedVote, vote, sk, kappa);

                // Store proofs
                PFDStruct value = PFDStruct.newValid(c_prime, vote, combinationProof, combinationDecryptionProof, voteDecryptionProof);
                pfd.add(value);

            } else { // m != 1
                System.out.println("--> CASE: M!=1");

                PFDStruct value = PFDStruct.newInvalid(c_prime, m, combinationProof, combinationDecryptionProof);
                pfd.add(value);
            }
        }
        
        return Pair.of(tallyOfVotes, pfd);
    }



    public static class Builder {
        private Random random;
        private ElGamal elgamal;
        private BulletinBoard bb;

        private Sigma1 sigma1;
        private Bulletproof bulletProof;
        private Sigma3 sigma3;
        private Sigma4 sigma4;
        private Mixnet mixnet;

        public AthenaTally build() {
            //Check that all fields are set
            if (random == null ||
                elgamal == null ||
                bb == null ||
                sigma1 == null ||
                bulletProof == null ||
                sigma3 == null ||
                sigma4 == null ||
                mixnet == null
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            AthenaTally obj = new AthenaTally();
            obj.random = random;
            obj.elgamal = elgamal;
            obj.bb = bb;
            obj.sigma1 = sigma1;
            obj.bulletProof = bulletProof;
            obj.sigma3 = sigma3;
            obj.sigma4 = sigma4;
            obj.mixnet = mixnet;

            return obj;
        }

        //Setters
        public Builder setRandom(Random random) {
            this.random = random;
            return this;
        }

        public Builder setElgamal(ElGamal elgamal) {
            this.elgamal = elgamal;
            return this;
        }

        public Builder setBb(BulletinBoard bb) {
            this.bb = bb;
            return this;
        }

        public Builder setSigma1(Sigma1 sigma1) {
            this.sigma1 = sigma1;
            return this;
        }

        public Builder setBulletProof(Bulletproof bulletProof) {
            this.bulletProof = bulletProof;
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
    }



}