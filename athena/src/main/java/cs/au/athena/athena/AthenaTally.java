package cs.au.athena.athena;

import cs.au.athena.GENERATOR;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.athena.strategy.Strategy;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.sigma.Sigma2Pedersen;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import cs.au.athena.dao.athena.*;
import cs.au.athena.dao.bulletproof.BulletproofExtensionStatement;
import cs.au.athena.dao.bulletproof.BulletproofStatement;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.mixnet.Mixnet;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma3;
import cs.au.athena.sigma.Sigma4;
import cs.au.athena.sigma.bulletproof.Bulletproof;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

public class AthenaTally {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("ATHENA-TALLY");


    private Random random;
    private Elgamal elgamal;
    private BulletinBoard bb;
    private Strategy strategy;
    private int kappa;

    // Construct using builder
    private AthenaTally() {}

    public TallyStruct Tally(SK_Vector skv, int nc) {
        ElGamalSK sk = skv.sk;
        ElGamalPK pk = sk.pk;

        /* ********
         * Step 1: Remove invalid ballots
         *********/
        logger.info(MARKER, "Tally(...) => step1");

        List<Ballot> validBallots = removeInvalidBallots(pk, this.bb);
        if (validBallots.isEmpty()) {
            logger.error("AthenaTally.Tally =>  Step 1 yielded no valid ballots on bulletin-board.");
            return null;
        }


        /* ********
         * Step 2: Mix final votes
         *********/
        logger.info(MARKER, "Tally(...) => step2");

        //Filter ReVotes and pfr proof of same nonce
        Pair<Map<MapAKey, MapAValue>, List<PFRStruct>> filterResult = filterReVotesAndProveSameNonce(validBallots, sk);
        Map<MapAKey, MapAValue> A = filterResult.getLeft();
        List<PFRStruct> pfr = filterResult.getRight();


//        assert A.values().stream()
//                .map(MapAValue::getCombinedCredential)
//                .map(combinedCredential -> cs.au.cs.au.athena.athena.elgamal.decrypt(combinedCredential, sk))
//                .allMatch(decryptedCombinedCredential -> decryptedCombinedCredential.equals(BigInteger.ONE)) : "Not equal 1 before mixing";


        // Perform random mix
        MixedBallotsAndProof mixPair = mixnet(A, pk);
        List<MixBallot> mixedBallots = mixPair.mixedBallots; // TODO: strategy
        MixProof mixProof = mixPair.mixProof;


//        assert mixedBallots.stream()
//                .map(MixBallot::getCombinedCredential)
//                .map(combCred -> cs.au.cs.au.athena.athena.elgamal.decrypt(combCred, sk))
//                .allMatch(decryptedCombinedCredential -> decryptedCombinedCredential.equals(BigInteger.ONE)) : "Not equal 1 after mixing";


        /* ********
         * Step 3: Reveal eligible votes
         *********/
        logger.info(MARKER, "Tally(...) => step3");

        // Tally eligible votes and prove computations
        Pair<Map<Integer, Integer>, List<PFDStruct>> revealPair = revealEligibleVotes(sk, mixedBallots, nc, kappa);
        Map<Integer, Integer> officialTally = revealPair.getLeft();

        if (officialTally == null) {
            System.out.println("AthenaTally.Tally -----------------> officialTally");
        }

        List<PFDStruct> pfd = revealPair.getRight();

        // Post (b, (pfr, B, pfd) ) to bulletin board
        bb.publishTallyOfVotes(officialTally);
        PFStruct pf = new PFStruct(pfr, mixedBallots, pfd, mixProof);
        bb.publishPF(pf);

        return new TallyStruct(officialTally, pf);
    }



    // Step 1 of Tally
    public static List<Ballot> removeInvalidBallots(ElGamalPK pk, BulletinBoard bb) {
        List<Ballot> finalBallots = new ArrayList<>(bb.retrievePublicBallots());

        for (Ballot ballot : bb.retrievePublicBallots()) {
            Ciphertext publicCredential = ballot.getPublicCredential();

            // Is the public credential
            boolean isPublicCredentialInL = bb.electoralRollContains(publicCredential);
            if (!isPublicCredentialInL) {
                System.err.println("AthenaTally.removeInvalidBallot => ballot posted with invalid public credential");
                finalBallots.remove(ballot);
            }

            // Verify that the negated private credential is in the valid range
            // ElGamal ciphertext (c1,c2) => use c2=g^(-d) h^s as Pedersen commitment of (-d) using randomness s
            Ciphertext encryptedNegatedPrivateCredential = ballot.getEncryptedNegatedPrivateCredential();

            // message/vector u used to make ballot proofs specific to the given ballot
            //  consists of (public credential, encrypted negated private credential, encrypted vote, counter)
            UVector uVector = new UVector(publicCredential, encryptedNegatedPrivateCredential, ballot.getEncryptedVote(), BigInteger.valueOf(ballot.getCounter()));

//            logger.info(ATHENA_TALLY_MARKER, "Verifying Sigma2Pedersen 1");
            boolean verify_encryptedNegatedPrivateCredential = Sigma2Pedersen.verifyCipher(
                    encryptedNegatedPrivateCredential,
                    ballot.proofNegatedPrivateCredential,
                    uVector,
                    pk);
//            logger.info(ATHENA_TALLY_MARKER, "Finished Sigma2Pedersen 1");


            // remove invalid ballots.
            if (!verify_encryptedNegatedPrivateCredential) {
                System.err.println("AthenaTally.removeInvalidBallot => Removing ballot: VerCiph(Enc_pk(-d), proof_{-d}) = 0");
                logger.error(MARKER, "AthenaTally.removeInvalidBallot => Removing ballot: VerCiph(Enc_pk(-d), proof_{-d}) = 0");
                finalBallots.remove(ballot);
            }

            // Verify that the vote is in the valid range
            // ElGamal ciphertext (c1,c2) => use c2=g^(v) h^t as Pedersen commitment of vote v using randomness t
            Ciphertext encryptedVote = ballot.getEncryptedVote();

            int nc = bb.retrieveNumberOfCandidates();
            BigInteger H = BigInteger.valueOf(nc - 1);
            BulletproofExtensionStatement stmnt_2 = new BulletproofExtensionStatement(
                    H,
                    new BulletproofStatement.Builder()
                            .setN(Bulletproof.getN(H))
                            .setV(encryptedVote.c2) // g^v h^t
                            .setPK(pk)
                            .set_G_Vector(bb.retrieve_G_VectorVote())
                            .set_H_Vector(bb.retrieve_H_VectorVote())
                            .setUVector(uVector)
                            .build()
            );


//            logger.info(ATHENA_TALLY_MARKER, "Verifying bulletproof 2");
            boolean verify_encVote = Bulletproof
                    .verifyStatementArbitraryRange(
                            stmnt_2,
                            ballot.getProofVotePair()
                    );
//            logger.info(ATHENA_TALLY_MARKER, "Finished bulletproof 2");


            // remove invalid ballots.
            if (!verify_encVote) {
                System.err.println("AthenaImpl.removeInvalidBallot => Removing ballot: VerCiph(Enc_pk(v), proof_{v}) = 0");
                logger.info(MARKER, "Removing ballot");
                finalBallots.remove(ballot);
            }
        }

        return finalBallots;
    }

    // Step 2 of Tally. Returns map of the highest counter ballot, for each credential pair, and a proof having used the same nonce for all ballots.
    private Pair<Map<MapAKey, MapAValue>, List<PFRStruct>> filterReVotesAndProveSameNonce(List<Ballot> ballots, ElGamalSK sk) {
        int ell = ballots.size();

        List<PFRStruct> pfr = new ArrayList<>();
        Map<MapAKey, MapAValue> A = new HashMap<>();

        // Pick a nonce to mask public credentials.
        BigInteger nonce_n = GENERATOR.generateUniqueNonce(BigInteger.ONE, sk.pk.group.q, this.random);

        // For each ballot.
        Ciphertext ci_prime_previous = null;
        for (int i = 0; i < ell; i++) {
            Ballot ballot = ballots.get(i);

            // Homomorpically reencrypt(by raising to power n) ballot and decrypt
            Ciphertext ci_prime = this.strategy.homoCombination(ballot.getEncryptedNegatedPrivateCredential(), nonce_n, sk.pk.group);

            // Dec(Enc(g^x)) = Dec((c1,c2)) = Dec((g^r,g^x * h^r)) = g^x
            BigInteger noncedNegatedPrivateCredentialElement = this.strategy.decrypt(ci_prime, sk);


            // Update map with highest counter entry.
            MapAKey key = new MapAKey(ballot.getPublicCredential(), noncedNegatedPrivateCredentialElement);
            MapAValue existingValue = A.get(key);
            MapAValue updatedValue = getHighestCounterEntry(existingValue, ballot, sk.pk.group.p);
            A.put(key, updatedValue);

            // Prove decryption
            Sigma3Proof decryptionProof = this.strategy.proveDecryption(ci_prime, noncedNegatedPrivateCredentialElement, sk, kappa);

            // Proove that the same nonce was used for all ballots.
            if (pfr.size() > 0) {
                // Prove c_{i−1} and c_{i} are derived by iterative homomorphic combination wrt nonce n
                List<Ciphertext> listCombined = Arrays.asList(ci_prime_previous, ci_prime);
                List<Ciphertext> listCiphertexts = Arrays.asList(ballots.get(i - 1).getEncryptedNegatedPrivateCredential(), ballot.getEncryptedNegatedPrivateCredential());
                Sigma4Proof omega = this.strategy.proveCombination(listCombined, listCiphertexts, nonce_n, sk, kappa);

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
    private MixedBallotsAndProof mixnet(Map<MapAKey, MapAValue> A, ElGamalPK pk) {
        // Cast to mix ballot list
        List<MixBallot> ballots = A.values().stream()
                .map(MapAValue::toMixBallot)
                .collect(Collectors.toList());

        return this.strategy.proveMix(ballots, pk, kappa);

    }

    // Step 3 of tally. Nonce and decrypt ballots, and keep a tally of the eligible votes.
    private Pair<Map<Integer, Integer>, List<PFDStruct>> revealEligibleVotes(ElGamalSK sk, List<MixBallot> mixedBallots, int nc, int kappa) {
        Map<Integer, Integer> officialTally = new HashMap<>();
        for (int candidates = 0; candidates < nc; candidates++) {
            officialTally.put(candidates, 0);
        }
        List<PFDStruct> pfd = new ArrayList<>(mixedBallots.size());
        BigInteger p = sk.pk.group.p;

        for (MixBallot mixBallot : mixedBallots) {
            Ciphertext combinedCredential = mixBallot.getCombinedCredential();
            Ciphertext encryptedVote = mixBallot.getEncryptedVote();

            // Apply a nonce to the combinedCredential
            BigInteger nonce = GENERATOR.generateUniqueNonce(BigInteger.ONE, sk.pk.group.q, this.random);
            Ciphertext c_prime = AthenaCommon.homoCombination(combinedCredential, nonce, p);

            // Decrypt nonced combinedCredential
            BigInteger m = Elgamal.decrypt(c_prime, sk);

            // Prove that c' is a homomorphic combination of combinedCredential
            Sigma4Proof combinationProof = this.strategy.proveCombination(List.of(c_prime),
                    List.of(combinedCredential),
                    nonce,
                    sk,
                    kappa);

            // Prove that msg m is the correct decryption of c'
            Sigma3Proof combinationDecryptionProof = this.strategy.proveDecryption(c_prime, m, sk, kappa);

            // Check validity of private credential. (decrypted combinedCredential = 1)
            if (m.equals(BigInteger.ONE)) {
                // Decrypt vote
                BigInteger voteElement = Elgamal.decrypt(encryptedVote, sk);
                Integer vote = elgamal.lookup(voteElement);

                // Tally the vote
                if (officialTally.containsKey(vote)) { // Check that map already has some votes for that candidate.
                    Integer totalVotes = officialTally.get(vote);
                    officialTally.put(vote, totalVotes + 1);
                } else { // First vote for the given candidate
                    officialTally.put(vote, 1);
                }

                // Prove correct decryption of vote
                Sigma3Proof voteDecryptionProof = this.strategy.proveDecryption(encryptedVote, voteElement, sk, kappa);

                // Store proofs
                PFDStruct value = PFDStruct.newValid(c_prime, voteElement, combinationProof, combinationDecryptionProof, voteDecryptionProof);
                pfd.add(value);

            } else { // m != 1
                System.out.println("AthenaTally.revealEligibleVotes CASE: M != 1  ");
                PFDStruct value = PFDStruct.newInvalid(c_prime, m, combinationProof, combinationDecryptionProof);
                pfd.add(value);
            }
        }

        return Pair.of(officialTally, pfd);
    }




    public static class Builder {
        private Elgamal elgamal;
        private AthenaFactory athenaFactory;
        private int kappa;


        //Setters
        public Builder setFactory(AthenaFactory athenaFactory) {
            this.athenaFactory = athenaFactory;
            return this;
        }

        public Builder setElgamal(Elgamal elgamal) {
            this.elgamal = elgamal;
            return this;
        }


        public Builder setKappa(int kappa) {
            this.kappa = kappa;
            return this;
        }

        public AthenaTally build() {
            //Check that all fields are set
            if (athenaFactory == null ||
                    elgamal == null ||
                    kappa == 0
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            AthenaTally athenaTally = new AthenaTally();
            athenaTally.elgamal = elgamal;
            athenaTally.strategy = this.athenaFactory.getStrategy();
            athenaTally.random = this.athenaFactory.getRandom();
            athenaTally.bb = this.athenaFactory.getBulletinBoard();
            athenaTally.kappa = kappa;

            return athenaTally;
        }
    }
}