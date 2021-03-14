package project.athena;

import project.CONSTANTS;
import project.dao.athena.Ballot;
import project.dao.athena.CredentialTuple;
import project.dao.athena.PK_Vector;
import project.dao.bulletproof.BulletproofProof;
import project.dao.bulletproof.BulletproofSecret;
import project.dao.bulletproof.BulletproofStatement;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.sigma.Sigma1;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class AthenaVote {
    private static final int kappa = CONSTANTS.KAPPA;

    private final Sigma1 sigma1;
    private final Bulletproof bulletProof;
    private final Random random;
    private final ElGamal elgamal;
    private final BulletinBoard bb;

    private AthenaVote(Sigma1 sigma1,
                       Bulletproof bulletProof,
                       Random random,
                       ElGamal elgamal,
                       BulletinBoard bb){

        this.sigma1 = sigma1;
        this.bulletProof = bulletProof;
        this.random = random;
        this.elgamal = elgamal;
        this.bb = bb;
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


        // Make negated private credential
        BigInteger negatedPrivateCredential = credentialTuple.privateCredential.negate();
        negatedPrivateCredential = negatedPrivateCredential.mod(q).add(q).mod(q);


        // Create encryption of negated private credential, i.e. g^{-d}
        BigInteger randomness_s = BigInteger.valueOf(random.nextLong()); // FIXME: Generate coins s
        Ciphertext encryptedNegatedPrivateCredential = elgamal.encrypt(negatedPrivateCredential, pk, randomness_s);


        // Create encryption of vote, i.e. g^{v}
        BigInteger voteAsBigInteger = BigInteger.valueOf(vote);
        BigInteger randomness_t = BigInteger.valueOf(random.nextLong()); // FIXME: Generate coins t
        Ciphertext encryptedVote = elgamal.encrypt(voteAsBigInteger, pk, randomness_t);


        // Get public values from bb.
        int rangeBitlengthOfNegatedPrivateCredential = bb.retrieveRangeNumberNegatedPrivCred(); 
        List<BigInteger> g_vector_negatedPrivateCredential = bb.retrieve_G_VectorNegPrivCred();
        List<BigInteger> h_vector_negatedPrivateCredential = bb.retrieve_H_VectorNegPrivCred();

        // Prove that negated private credential -d resides in Z_q (this is defined using n)
        BulletproofStatement stmnt_1 = new BulletproofStatement(
                rangeBitlengthOfNegatedPrivateCredential,
                encryptedNegatedPrivateCredential.c2,
                pk,
                g_vector_negatedPrivateCredential,
                h_vector_negatedPrivateCredential);
        BulletproofSecret secret_1 = new BulletproofSecret(negatedPrivateCredential, randomness_s);
        BulletproofProof proofRangeOfNegatedPrivateCredential = bulletProof.proveStatement(stmnt_1, secret_1);
//        BulletproofProof proofRangeOfNegatedPrivateCredential = null;


        int rangeBitlengthOfVote = bb.retrieveRangeNumberVote();
        List<BigInteger> g_vector_vote = bb.retrieve_G_VectorVote();
        List<BigInteger> h_vector_vote = bb.retrieve_H_VectorVote();


        // Prove that vote v resides in [0,nc-1] (this is defined using n)
        BulletproofStatement stmnt_2 = new BulletproofStatement(
                rangeBitlengthOfVote,
                encryptedVote.c2,
                pk,
                g_vector_vote,
                h_vector_vote);
        BulletproofSecret secret_2 = new BulletproofSecret(voteAsBigInteger, randomness_t);
        BulletproofProof proofRangeOfVote = bulletProof.proveStatement(stmnt_2, secret_2);
//        BulletproofProof proofRangeOfVote = null;

        Ballot ballot = new Ballot(publicCredential, encryptedNegatedPrivateCredential, encryptedVote, proofRangeOfNegatedPrivateCredential, proofRangeOfVote, cnt);
        bb.publishBallot(ballot);
        return ballot;
    }

    public static class Builder {
        private Sigma1 sigma1;
        private Bulletproof bulletProof;
        private Random random;
        private ElGamal elgamal;
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


        public Builder setBB(BulletinBoard bb) {
            this.bb = bb;
            return this;
        }



        public AthenaVote build() {
            //Check that all fields are set
            if (
                            bb == null ||
                            random == null ||
                            sigma1 == null ||
                            bulletProof == null ||
                            elgamal == null

            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            return new AthenaVote(sigma1, bulletProof, random, elgamal, bb);
        }
    }


}
