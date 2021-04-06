package cs.au.athena.athena;

import cs.au.athena.UTIL;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.athena.CredentialTuple;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.athena.UVector;
import cs.au.athena.dao.bulletproof.BulletproofExtensionStatement;
import cs.au.athena.dao.bulletproof.BulletproofProof;
import cs.au.athena.dao.bulletproof.BulletproofSecret;
import cs.au.athena.dao.bulletproof.BulletproofStatement;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.bulletproof.Bulletproof;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class AthenaVote {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker ATHENA_VOTE_MARKER = MarkerFactory.getMarker("ATHENA-VOTE");


    private Sigma1 sigma1;
    private Bulletproof bulletProof;
    private Random random;
    private ElGamal elgamal;
    private int kappa;
    private BulletinBoard bb;

    private AthenaVote() {}

    public Ballot Vote(
            CredentialTuple credentialTuple,
            PK_Vector pkv,
            int vote,
            int cnt,
            int nc) {


        if (!AthenaCommon.parsePKV(pkv)) {
            System.err.println("AthenaImpl.Vote => ERROR: pkv null");
            return null;
        }

        if (!AthenaCommon.verifyKey(sigma1, pkv, kappa)) {
            System.err.println("AthenaImpl.Vote => ERROR: VerifyKey(...) => false");
            return null;
        }


        boolean vote_in_range = vote >= 0 && vote < nc;
        boolean not_in_message_space = BigInteger.valueOf(nc).compareTo(pkv.pk.group.q) >= 0; // Should be in Z_q
        if (!vote_in_range || not_in_message_space) {
            System.err.println("AthenaImpl.Vote => ERROR: v not in {1...nc}");
            return null;
        }

        Ciphertext publicCredential = credentialTuple.publicCredential;
        ElGamalPK pk = pkv.pk;
        BigInteger q = pk.group.q;
        BigInteger p = pk.group.p;


        // Make negated private credential
        BigInteger negatedPrivateCredential = credentialTuple.privateCredential.negate();
        negatedPrivateCredential = negatedPrivateCredential.mod(q).add(q).mod(q);

        assert negatedPrivateCredential.add(credentialTuple.privateCredential).mod(q).equals(BigInteger.ZERO) : "-d + d != 0";


        // Create encryption of negated private credential
        BigInteger randomness_s = UTIL.getRandomElement(q, random);
        Ciphertext encryptedNegatedPrivateCredential = elgamal.exponentialEncrypt(negatedPrivateCredential, pk, randomness_s);

        // Create encryption of vote,
        BigInteger voteAsBigInteger = BigInteger.valueOf(vote);
        BigInteger randomness_t = UTIL.getRandomElement(q, random);
        Ciphertext encryptedVote = elgamal.exponentialEncrypt(voteAsBigInteger, pk, randomness_t);

        // message/vector u used to make ballot proofs specific to the given ballot
        //  consists of (public credential, encrypted negated private credential, encrypted vote, counter)
        UVector uVector = new UVector(publicCredential, encryptedNegatedPrivateCredential, encryptedVote, BigInteger.valueOf(cnt));

        // Prove that for negated private credential -d that d is in [0, 2^{\lfloor log_2 q \rfloor} -1]
        List<BigInteger> g_vector_negatedPrivateCredential = bb.retrieve_G_VectorNegPrivCred();
        List<BigInteger> h_vector_negatedPrivateCredential = bb.retrieve_H_VectorNegPrivCred();
        int n = Bulletproof.getN(q) - 1; //q.bitlength()-1

        BulletproofStatement stmnt_1 = new BulletproofStatement.Builder()
                .setN(n)
                .setV(encryptedNegatedPrivateCredential.c2.modInverse(p)) // (g^{-d} h^s)^{-1} =>(g^{d} h^{-s})
                .setPK(pk)
                .set_G_Vector(g_vector_negatedPrivateCredential)
                .set_H_Vector(h_vector_negatedPrivateCredential)
                .setUVector(uVector)
                .build();

        /*****
         * NEW IMPLEMENTATION WITH Sigma Pedersen.
         */


        // negate since we take the inverse of the commitment
        BulletproofSecret secret_1 = new BulletproofSecret(negatedPrivateCredential.negate().mod(q).add(q).mod(q), randomness_s.negate().mod(q).add(q).mod(q));
        BulletproofProof proofRangeOfNegatedPrivateCredential = bulletProof.proveStatement(stmnt_1, secret_1);

        // Prove that vote v resides in [0,nc-1] (this is defined using n)
        List<BigInteger> g_vector_vote = bb.retrieve_G_VectorVote();
        List<BigInteger> h_vector_vote = bb.retrieve_H_VectorVote();
        BigInteger H = BigInteger.valueOf(nc - 1);
        BulletproofExtensionStatement stmnt_2 = new BulletproofExtensionStatement(
                H,
                new BulletproofStatement.Builder()
                        .setN(Bulletproof.getN(H))
                        .setV(encryptedVote.c2) // g^v h^t
                        .setPK(pk)
                        .set_G_Vector(g_vector_vote)
                        .set_H_Vector(h_vector_vote)
                        .setUVector(uVector)
                        .build());

        BulletproofSecret secret_2 = new BulletproofSecret(voteAsBigInteger, randomness_t);
        Pair<BulletproofProof, BulletproofProof> proofRangeOfVotePair = bulletProof.proveStatementArbitraryRange(stmnt_2, secret_2);

        Ballot ballot = new Ballot.Builder()
                .setPublicCredential(publicCredential)
                .setEncryptedNegatedPrivateCredential(encryptedNegatedPrivateCredential)
                .setEncryptedVote(encryptedVote)
                .setProofVotePair(proofRangeOfVotePair)
                .setProofNegatedPrivateCredential(proofRangeOfNegatedPrivateCredential)
                .setCounter(cnt)
                .build();

        // returns the vote.
        return ballot;
    }










    public static class Builder {
        private Sigma1 sigma1;
        private Bulletproof bulletProof;
        private Random random;
        private ElGamal elgamal;
        private int kappa;
        private BulletinBoard bb;


        public Builder setSigma1(Sigma1 sigma1) {
            this.sigma1 = sigma1;
            return this;
        }

        public Builder setBulletProof(Bulletproof bulletProof) {
            this.bulletProof = bulletProof;
            return this;
        }

        public Builder setRandom(Random random) {
            this.random = random;
            return this;
        }

        public Builder setElGamal(ElGamal elgamal) {
            this.elgamal = elgamal;
            return this;
        }

        public Builder setKappa(int kappa) {
            this.kappa = kappa;
            return this;
        }

        public Builder setBB(BulletinBoard bb) {
            this.bb = bb;
            return this;
        }


        public AthenaVote build() {
            //Check that all fields are set
            if (bb == null ||
                random == null ||
                sigma1 == null ||
                bulletProof == null ||
                elgamal == null ||
                kappa == 0
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            AthenaVote athenaVote = new AthenaVote();
            athenaVote.sigma1 = this.sigma1;
            athenaVote.bulletProof = this.bulletProof;
            athenaVote.random = this.random;
            athenaVote.elgamal = this.elgamal;
            athenaVote.bb = this.bb;
            athenaVote.kappa = this.kappa;

            return athenaVote;

        }
    }


}
