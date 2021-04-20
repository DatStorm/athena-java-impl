package cs.au.athena.athena.strategy;

import cs.au.athena.CONSTANTS;
import cs.au.athena.GENERATOR;
import cs.au.athena.athena.AthenaCommon;

import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.mixnet.Mixnet;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma4;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class SingleTallierStrategy implements Strategy {

    AthenaFactory athenaFactory;
    public SingleTallierStrategy(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
    }


    @Override
    public Group getGroup() {
        Random random = athenaFactory.getRandom();
        // return Group.generateGroup(bitlength, random);
        return CONSTANTS.ELGAMAL_CURRENT.GROUP;
    }

    @Override
    public ElGamalSK setup(int tallierIndex, int nc, int kappa) {
        if (tallierIndex != 0) {
            System.out.println("SingleTallierStrategy.setup: You only have one tallierSo it should be 1.");
        }
//        BulletinBoardV2_0 bb = athenaFactory.getBulletinBoard();
        BulletinBoard bb = BulletinBoard.getInstance(); // TODO: RePLACE WITH ABOVE WHEN BB IS DONE!
        Random random = athenaFactory.getRandom();

        // Get the group
        Group group = this.getGroup();

        // Create elgamal and generate keys
        ElGamalSK sk = Elgamal.generateSK(group, random);
        ElGamalPK pk = sk.pk;
        Sigma1Proof rho = this.proveKey(pk, sk, kappa);



        // mb, mc is upper-bound by a polynomial in the security parameter
//        int mb =CONSTANTS.MB;
//        BigInteger mc = BigInteger.valueOf(CONSTANTS.MC);

        List<List<BigInteger>> generators = GENERATOR.generateRangeProofGenerators(pk, nc);
        List<BigInteger> g_vector_vote = generators.get(0);
        List<BigInteger> h_vector_vote = generators.get(1);

        bb.publishNumberOfCandidates(nc);
        bb.publish_G_VectorVote(g_vector_vote);
        bb.publish_H_VectorVote(h_vector_vote);

        PK_Vector pkv = new PK_Vector(pk, rho);
        bb.publishPKV(pkv);

        return sk;
    }

    @Override
    public Sigma1Proof proveKey(ElGamalPK pk, ElGamalSK sk, int kappa) {
        Sigma1 sigma1 = athenaFactory.getSigma1();
        Random random = athenaFactory.getRandom();

        return sigma1.ProveKey(pk, sk, random, kappa);

    }

    @Override
    public boolean verifyKey(ElGamalPK pk, Sigma1Proof rho, int kappa) {
        Sigma1 sigma1 = athenaFactory.getSigma1();
        return sigma1.VerifyKey(pk, rho, kappa);
    }

    @Override
    public Sigma3Proof proveDecryption(Ciphertext c, BigInteger M, ElGamalSK sk, int kappa) {
        // I am tallier T_0
        // Publish sigma3 proof
        return athenaFactory.getSigma3().proveDecryption(c, M, sk, kappa);
    }

    @Override
    public boolean verifyDecryption(Ciphertext c, BigInteger M, ElGamalPK pk, Sigma3Proof phi, int kappa) {
        return athenaFactory.getSigma3().verifyDecryption(c, M, pk, phi, kappa);
    }

    @Override
    public Sigma4Proof proveCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, BigInteger nonce_n, ElGamalSK sk, int kappa) {
        return athenaFactory.getSigma4().proveCombination(sk, listOfCombinedCiphertexts, listCiphertexts, nonce_n, kappa);
    }

    @Override
    public boolean verifyCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, Sigma4Proof omega, ElGamalPK pk, int kappa) {
        Sigma4 sigma4 = athenaFactory.getSigma4();

        return sigma4.verifyCombination(pk, listOfCombinedCiphertexts, listCiphertexts, omega, kappa);
    }

    @Override
    public MixedBallotsAndProof proveMix(List<MixBallot> ballots, ElGamalPK pk, int kappa) {
        Mixnet mixnet = athenaFactory.getMixnet();
        return mixnet.mixAndProveMix(ballots, pk, kappa);
    }

    @Override
    public boolean verifyMix(MixStatement statement, MixProof proof, ElGamalPK pk, int kappa) {
        Mixnet mixnet = athenaFactory.getMixnet();
        return mixnet.verify(statement, proof, pk, kappa);
    }


    @Override
    public Ciphertext homoCombination(Ciphertext c, BigInteger nonce, Group group) {
        return AthenaCommon.homoCombination(c, nonce, group.p);
    }

    @Override
    public BigInteger decrypt(int tallierIndex, Ciphertext c, ElGamalSK sk, int kappa) {
        return Elgamal.decrypt(c, sk);
    }




}
