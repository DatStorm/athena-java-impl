package cs.au.athena.athena;

import cs.au.athena.GENERATOR;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.athena.bulletinboard.VerifyingBulletinBoardV2_0;
import cs.au.athena.athena.distributed.AthenaDistributed;
import cs.au.athena.elgamal.*;
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
    private BulletinBoardV2_0 bb;
    private VerifyingBulletinBoardV2_0 vbb;
    private AthenaDistributed distributed;
    private int tallierIndex;
    private int kappa;

    // Construct using builder
    private AthenaTally() {}

    public Map<Integer, Integer> Tally(int tallierIndex, ElGamalSK skShare, int nc) {
        ElGamalPK pk = vbb.retrieveAndVerifyPK();

        /* ********
         * Step 1: Remove invalid ballots
         *********/

        logger.info(MARKER, "Step 1. Remove invalid ballots");
        List<Ballot> validBallots = removeInvalidBallots(pk, this.bb);
        if (validBallots.isEmpty()) {
            logger.error("AthenaTally.Tally =>  Step 1 yielded no valid ballots on bulletin-board.");
            throw new RuntimeException("Step 1 yielded no valid ballots on bulletin-board.");
        }


        /* ********
         * Step 2: Mix final votes
         *********/

        //Filter ReVotes and pfr proof of same nonce
        logger.info(MARKER, "Step 2a. Filter ReVotes");
        Map<MapAKey, MapAValue> A = filterReVotes(tallierIndex, validBallots, skShare);

        // Perform random mix
        logger.info(MARKER, "Step 2b.Mixnet");
        MixedBallotsAndProof mixPair = mixnet(A, pk);
        List<MixBallot> mixedBallots = mixPair.mixedBallots;
        MixProof mixProof = mixPair.mixProof;


        /* ********
         * Step 3: Reveal eligible votes
         *********/

        logger.info(MARKER, "step 3. Reveal authorised votes");
        // Tally eligible votes and prove computations
        Pair<Map<Integer, Integer>, List<PFDStruct>> revealPair = revealAuthorisedVotes(skShare, mixedBallots, nc, kappa);
        Map<Integer, Integer> officialTally = revealPair.getLeft();

        if (officialTally == null) {
            System.out.println("AthenaTally.Tally -----------------> officialTally");
        }

        // Post tallyboard
        bb.publishTallyOfVotes(officialTally);

        return officialTally;
    }



    // Step 1 of Tally
    public static List<Ballot> removeInvalidBallots(ElGamalPK pk, BulletinBoardV2_0 bb) {
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
    private Map<MapAKey, MapAValue> filterReVotes(int tallierIndex, List<Ballot> ballots, ElGamalSK sk) {
        int ell = ballots.size();
        Map<MapAKey, MapAValue> A = new HashMap<>();

        // Pick a nonce to mask public credentials.
        BigInteger nonce_n = GENERATOR.generateUniqueNonce(BigInteger.ONE, sk.pk.group.q, this.random);

        // Collaborate with other talliers, to apply a nonce to all ciphertexts
        List<Ciphertext> combinedCiphertexts = this.distributed.performPfrPhaseOneHomoComb(tallierIndex, ballots, nonce_n, sk, kappa);

        // Collaborate with other talliers, to decrypt combined ciphertexts
        List<BigInteger> listOfNoncedNegatedPrivateCredentialElement = this.distributed.performPfrPhaseTwoDecryption(tallierIndex, combinedCiphertexts, sk, kappa);

        // MapA
        for (int i = 0; i < ell; i++) {
            Ballot ballot = ballots.get(i);
            BigInteger N = listOfNoncedNegatedPrivateCredentialElement.get(i);

            // Update map with highest counter entry.
            MapAKey key = new MapAKey(ballot.getPublicCredential(), N);
            MapAValue existingValue = A.get(key);
            MapAValue updatedValue = getHighestCounterEntry(existingValue, ballot, sk.pk.group);
            A.put(key, updatedValue);
        }

        return A;
    }

    // Step 2 of Tally. Returns a MapAValue, representing the ballot with the highest counter.
    public static MapAValue getHighestCounterEntry(MapAValue existingValue, Ballot ballot, Group group) {
        // Update the map entry if the old counter is less. Nullify if equal
        int counter = ballot.getCounter();
        if (existingValue == null || existingValue.getCounter() < counter) {
            // Update the map if A[(bi[1]; N)] is empty, or contains a lower counter
            Ciphertext combinedCredential = ballot.getPublicCredential().multiply(ballot.getEncryptedNegatedPrivateCredential(), group.p);
            return new MapAValue(counter, combinedCredential, ballot.getEncryptedVote());
        } else if (existingValue.getCounter() == counter) {
            // Duplicate counters are illegal. Set null entry.
            return new MapAValue(counter, null, null);
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

        return this.distributed.proveMix(ballots, pk, kappa);

    }

    // Step 3 of tally. Nonce and decrypt ballots, and keep a tally of the eligible votes.
    private Pair<Map<Integer, Integer>, List<PFDStruct>> revealAuthorisedVotes(ElGamalSK sk, List<MixBallot> mixedBallots, int nc, int kappa) {
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
            Ciphertext c_prime = AthenaCommon.homoCombination(combinedCredential, nonce, sk.pk.group);

            // Prove that c' is a homomorphic combination of combinedCredential
            Sigma4Proof combinationProof = this.distributed.proveCombination(List.of(c_prime),
                    List.of(combinedCredential),
                    nonce,
                    sk,
                    kappa);

            // Decrypt nonced combinedCredential
            BigInteger m = Elgamal.decrypt(c_prime, sk);

            // Prove that msg m is the correct decryption of c'
            Sigma3Proof combinationDecryptionProof = this.distributed.proveDecryption(c_prime, m, sk, kappa);

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
                Sigma3Proof voteDecryptionProof = this.distributed.proveDecryption(encryptedVote, voteElement, sk, kappa);

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
        private int tallierIndex;
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

        public Builder setTallierIndex(int tallierIndex) {
            this.tallierIndex = tallierIndex;
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
            athenaTally.distributed = this.athenaFactory.getDistributedAthena();
            athenaTally.random = this.athenaFactory.getRandom();
            athenaTally.bb = this.athenaFactory.getBulletinBoard();
            athenaTally.kappa = kappa;
            athenaTally.tallierIndex = tallierIndex;

            return athenaTally;
        }
    }
}