package cs.au.athena.athena;

import cs.au.athena.GENERATOR;
import cs.au.athena.UTIL;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.VerifyingBB;
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
import cs.au.athena.sigma.bulletproof.Bulletproof;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

public class AthenaTally {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("ATHENA-TALLY");

    private Random random;
    private BulletinBoardV2_0 bb;
    private VerifyingBB vbb;
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
        logger.info(MARKER, "Removing invalid ballots phase");
        List<Ballot> validBallots = removeInvalidBallots(pk, this.bb, this.vbb);
        if (validBallots.isEmpty()) {
            logger.error(MARKER,"T"+ tallierIndex+ ": AthenaTally.Tally =>  Step 1 yielded no valid ballots on bulletin-board.");
            throw new RuntimeException("Step 1 yielded no valid ballots on bulletin-board.");
        }



        /* ********
         * Step 2: Mix final votes
         *********/
        //Filter ReVotes and pfr proof of same nonce
        logger.info(MARKER, String.format("T%02d: Filtering ReVotes", tallierIndex));
        List<MixBallot> filteredBallots = filterReVotes(tallierIndex, validBallots, skShare);

//        logger.info(MARKER, String.format("T%d completed filter revotes: %s", tallierIndex, A.values().stream().findFirst().toString()));



        // Perform random mix
        logger.info(MARKER, String.format("T%02d: Mixnet", tallierIndex));


        /** TODO: COMMENT BACK IN WHEN DONE! */
//        List<MixBallot> mixedBallots = this.distributed.performMixnet(tallierIndex, filteredBallots, pk, kappa);
        List<MixBallot> mixedBallots = filteredBallots;



        /* ********
         * Step 3: Reveal eligible votes
         *********/
        logger.info(MARKER, String.format("T%02d: Revealing authorised votes", tallierIndex));

        // Tally eligible votes and prove computations
        Map<Integer, Integer> officialTally = revealAuthorisedVotes(mixedBallots, skShare, kappa);

        // Post tallyboard
        bb.publishTallyOfVotes(tallierIndex, officialTally);
        return officialTally;
    }


    // Step 1 of Tally
    public static List<Ballot> removeInvalidBallots(ElGamalPK pk, BulletinBoardV2_0 bb, VerifyingBB vbb) {
        List<Ballot> finalBallots = new ArrayList<>(bb.retrievePublicBallots());

        for (Ballot ballot : bb.retrievePublicBallots()) {
            Ciphertext publicCredential = ballot.getPublicCredential();

            // Is the public credential
            boolean isPublicCredentialInL = bb.electoralRollContains(publicCredential);
            if (!isPublicCredentialInL) {
                logger.info(MARKER, "removeInvalidBallots => ballot posted with invalid public credential");
                finalBallots.remove(ballot);
            }

            // Verify that the negated private credential is in the valid range
            // ElGamal ciphertext (c1,c2) => use c2=g^(-d) h^s as Pedersen commitment of (-d) using randomness s
            Ciphertext encryptedNegatedPrivateCredential = ballot.getEncryptedNegatedPrivateCredential();

            // message/vector u used to make ballot proofs specific to the given ballot
            //  consists of (public credential, encrypted negated private credential, encrypted vote, counter)
            UVector uVector = new UVector(publicCredential, encryptedNegatedPrivateCredential, ballot.getEncryptedVote(), BigInteger.valueOf(ballot.getCounter()));

            boolean verify_encryptedNegatedPrivateCredential = Sigma2Pedersen.verifyCipher(
                    encryptedNegatedPrivateCredential,
                    ballot.proofNegatedPrivateCredential,
                    uVector,
                    pk);

            // remove invalid ballots.
            if (!verify_encryptedNegatedPrivateCredential) {
                logger.error(MARKER, "removeInvalidBallots => Removing ballot: VerCiph(Enc_pk(-d), proof_{-d}) = 0");
                finalBallots.remove(ballot);
            }

            // Verify that the vote is in the valid range
            // ElGamal ciphertext (c1,c2) => use c2=g^(v) h^t as Pedersen commitment of vote v using randomness t
            Ciphertext encryptedVote = ballot.getEncryptedVote();

            int nc = bb.retrieveNumberOfCandidates();
            BigInteger H = BigInteger.valueOf(nc - 1);
            Pair<List<BigInteger>, List<BigInteger>> g_and_h_vectors = vbb.retrieve_G_and_H_VectorVote();
            List<BigInteger> g_vector_vote = g_and_h_vectors.getLeft();
            List<BigInteger> h_vector_vote = g_and_h_vectors.getRight();

            BulletproofExtensionStatement stmnt_2 = new BulletproofExtensionStatement(
                    H,
                    new BulletproofStatement.Builder()
                            .setN(Bulletproof.getN(H))
                            .setV(encryptedVote.c2) // g^v h^t
                            .setPK(pk)
                            .set_G_Vector(g_vector_vote)
                            .set_H_Vector(h_vector_vote)
                            .setUVector(uVector)
                            .build()
            );

            boolean verify_encVote = Bulletproof
                    .verifyStatementArbitraryRange(
                            stmnt_2,
                            ballot.getProofVotePair()
                    );

            // remove invalid ballots.
            if (!verify_encVote) {
                System.err.println("removeInvalidBallot => Removing ballot: VerCiph(Enc_pk(v), proof_{v}) = 0");
                logger.info(MARKER, "Removing ballot");
                finalBallots.remove(ballot);
            }
        }

        return finalBallots;
    }

    // Step 2 of Tally. Returns map of the highest counter ballot, for each credential pair, and a proof having used the same nonce for all ballots.
    private List<MixBallot> filterReVotes(int tallierIndex, List<Ballot> validBallots, ElGamalSK sk) {

        // Pick a nonce to mask public credentials.
        BigInteger nonce_n = GENERATOR.generateUniqueNonce(BigInteger.ONE, sk.pk.group.q, this.random);

        // Collaborate with other talliers, to apply a nonce to all ciphertexts
        List<Ciphertext> noncedEncryptedNegatedPrivateCredentials = this.distributed.performPfrPhaseOneHomoComb(tallierIndex, validBallots, nonce_n, sk, kappa);

        // Collaborate with other talliers, to decrypt combined ciphertexts
        List<BigInteger> noncedNegatedPrivateCredentials = this.distributed.performPfrPhaseTwoDecryption(tallierIndex, noncedEncryptedNegatedPrivateCredentials, sk, kappa);

        // MapA
        List<MixBallot> ballots = performMapA(validBallots, noncedNegatedPrivateCredentials, sk.pk.group);

        return ballots;
    }

    // Does the filtering. Read the athena paper for documentation.
    public static List<MixBallot> performMapA(List<Ballot> validBallots, List<BigInteger> listOfNoncedNegatedPrivateCredentialElement, Group group) {
        int ell = validBallots.size();

        Map<MapAKey, MapAValue> A = new HashMap<>();
        for (int i = 0; i < ell; i++) {
            Ballot ballot = validBallots.get(i);
            BigInteger N = listOfNoncedNegatedPrivateCredentialElement.get(i);
            MapAKey key = new MapAKey(ballot.getPublicCredential(), N);

            // Update map with highest counter entry.
            MapAValue existingValue = A.get(key);
            MapAValue updatedValue = getHighestCounterEntry(existingValue, ballot, group);
            A.put(key, updatedValue);
        }

        // Convert map values to "ordered" list
        List<MixBallot> ballots = new ArrayList<>();
        for (int i = 0; i < ell; i++){
            Ballot ballot = validBallots.get(i);
            BigInteger N = listOfNoncedNegatedPrivateCredentialElement.get(i);
            MapAKey key = new MapAKey(ballot.getPublicCredential(), N);

            if (!A.containsKey(key)) {
                logger.error(MARKER, "A.keys(..) does not contain this key!");
            }

            MapAValue mapAValue = A.get(key);
            if (mapAValue == null) {
                logger.error(MARKER, "NULL. So the key generated is wrong.");
            }
            assert mapAValue != null : "Make sure that the key is not null! ";
            MixBallot mixBallot = mapAValue.toMixBallot();
            ballots.add(mixBallot);
        }
        return ballots;
    }

    // Step 2 of Tally. Returns a MapAValue, representing the ballot with the highest counter.
    public static MapAValue getHighestCounterEntry(MapAValue existingValue, Ballot ballot, Group group) {
        // Update the map entry if the old counter is less. Nullify if equal
        int counter = ballot.getCounter();
        if (existingValue == null || existingValue.getCounter() < counter) {
            // Update the map if A[(bi[1]; N)] is empty, or contains a lower counter
            Ciphertext combinedCredential = ballot.getPublicCredential().multiply(ballot.getEncryptedNegatedPrivateCredential(), group);
            return new MapAValue(counter, combinedCredential, ballot.getEncryptedVote());
        } else if (existingValue.getCounter() == counter) {
            // Duplicate counters are illegal. Set null entry.
            return new MapAValue(counter, null, null);
        } else {
            return existingValue;
        }
    }

    // Step 3 of tally. Nonce and decrypt ballots, and keep a tally of the eligible votes.
    private Map<Integer, Integer> revealAuthorisedVotes(List<MixBallot> mixedBallots, ElGamalSK sk, int kappa) {
        int nc = bb.retrieveNumberOfCandidates();

        List<Ciphertext> combinedCredentials = mixedBallots
                .stream()
                .map(MixBallot::getCombinedCredential)
                .collect(Collectors.toList());

        List<Ciphertext> encryptedVotes = mixedBallots
                .stream()
                .map(MixBallot::getEncryptedVote)
                .collect(Collectors.toList());

        // Phase I. Nonced combinedCredential
        List<Ciphertext> combinedCredentialsWithNonce = this.distributed.performPfdPhaseOneHomoComb(tallierIndex, combinedCredentials, random, sk, kappa);

        // Phase II. Decrypt nonced combinedCredential
        List<BigInteger> m_list = this.distributed.performPfdPhaseTwoDecryption(tallierIndex, combinedCredentialsWithNonce, sk, kappa);
//        logger.info(MARKER, String.format("T%d: m_list=[ %s ]", tallierIndex, UTIL.ballotListToString(m_list)));



        // Phase III. Decrypt authorized votes
        List<BigInteger> voteElements = this.distributed.performPfdPhaseThreeDecryption(tallierIndex, m_list, encryptedVotes, sk, kappa);
        logger.info(MARKER, String.format("T%02d: computing tally with -> |votes|= %d", tallierIndex, voteElements.size()));

        return computeTally(voteElements, nc, sk.pk.group);
    }

    public static Map<Integer, Integer> computeTally(List<BigInteger> voteElements, int nc, Group group) {
        Map<BigInteger, Integer> lookupTable = ElGamal.generateLookupTable(group, nc);

        // Lookup to go from g^v to v
        List<Integer> votes = voteElements.stream()
                .map(lookupTable::get)
                .collect(Collectors.toList());

        // Init tally map
        Map<Integer, Integer> officialTally = new HashMap<>();
        for (int candidates = 0; candidates < nc; candidates++) {
            officialTally.put(candidates, 0);
        }

        // Tally votes
        for(Integer vote : votes) {
//            assert officialTally.containsKey(vote); // All votes have performed rangeproof for their vote. We don't need to check
            Integer totalVotes = officialTally.get(vote);
            officialTally.put(vote, totalVotes + 1);
        }
        return officialTally;
    }


    public static class Builder {
        private AthenaFactory athenaFactory;
        private int tallierIndex;
        private int kappa;


        //Setters
        public Builder setFactory(AthenaFactory athenaFactory) {
            this.athenaFactory = athenaFactory;
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
                    kappa == 0
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            AthenaTally athenaTally = new AthenaTally();
            athenaTally.distributed = this.athenaFactory.getDistributedAthena();
            athenaTally.random = this.athenaFactory.getRandom();
            athenaTally.bb = this.athenaFactory.getBulletinBoard();
            athenaTally.vbb = this.athenaFactory.getVerifyingBulletinBoard();
            athenaTally.kappa = kappa;
            athenaTally.tallierIndex = tallierIndex;

            return athenaTally;
        }
    }
}