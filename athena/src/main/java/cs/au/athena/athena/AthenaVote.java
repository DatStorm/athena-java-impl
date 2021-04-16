package cs.au.athena.athena;

import cs.au.athena.UTIL;
import cs.au.athena.athena.strategy.Strategy;
import cs.au.athena.dao.Sigma2Pedersen.Sigma2PedersenProof;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.sigma.Sigma2Pedersen;
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
import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.bulletproof.Bulletproof;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class AthenaVote {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("ATHENA-VOTE");

    private Bulletproof bulletProof;
    private Random random;
    private Elgamal elgamal;
    private int kappa;
    private Strategy strategy;
    private BulletinBoard bb;
    private Sigma2Pedersen sigma2Pedersen;

    private AthenaVote() {
    }

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

        if (!this.strategy.verifyKey(pkv.pk, pkv.rho, kappa)) {
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

        // Make negated private credential
        BigInteger negatedPrivateCredential = credentialTuple.privateCredential.negate().mod(q).add(q).mod(q);
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

        // Proof of knowledge of encryptedNegatedPrivateCredential
        Sigma2PedersenProof proofNegatedPrivateCredential = sigma2Pedersen.proveCipher(
                encryptedNegatedPrivateCredential,
                negatedPrivateCredential,
                randomness_s,
                uVector,
                pk);



        // Proof on knowledge of encryptedVote
        // Prove that vote v resides in [0, nc-1] (this is defined using n)
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

        // returns the vote.
        return new Ballot.Builder()
                .setPublicCredential(publicCredential)
                .setEncryptedNegatedPrivateCredential(encryptedNegatedPrivateCredential)
                .setEncryptedVote(encryptedVote)
                .setProofVotePair(proofRangeOfVotePair)
                .setProofNegatedPrivateCredential(proofNegatedPrivateCredential)
                .setCounter(cnt)
                .build();
    }


    public static class Builder {
        private Elgamal elgamal;
        private int kappa;
        private AthenaFactory athenaFactory;


        public Builder setFactory(AthenaFactory athenaFactory) {
            this.athenaFactory = athenaFactory;
            return this;
        }

        public Builder setElGamal(Elgamal elgamal) {
            this.elgamal = elgamal;
            return this;
        }

        public Builder setKappa(int kappa) {
            this.kappa = kappa;
            return this;
        }

        public AthenaVote build() {
            //Check that all fields are set
            if (athenaFactory == null ||
                    elgamal == null ||
                    kappa == 0
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            AthenaVote athenaVote = new AthenaVote();
            athenaVote.strategy = this.athenaFactory.getStrategy();
            athenaVote.sigma2Pedersen = this.athenaFactory.getSigma2Pedersen();
            athenaVote.bulletProof = this.athenaFactory.getBulletProof();
            athenaVote.random = this.athenaFactory.getRandom();
            athenaVote.elgamal = this.elgamal;
            athenaVote.bb = this.athenaFactory.getBulletinBoard();
            athenaVote.kappa = this.kappa;

            return athenaVote;
        }
    }
}
