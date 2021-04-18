package cs.au.athena.athena.strategy;

import cs.au.athena.CONSTANTS;
import cs.au.athena.GENERATOR;
import cs.au.athena.athena.AthenaCommon;

import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.Randomness;
import cs.au.athena.dao.athena.ElectionSetup;
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
    public Group getGroup(int bitlength, Random random) {
        // return Group.generateGroup(bitlength, random);
        return CONSTANTS.ELGAMAL_CURRENT.GROUP;
    }

    @Override
    public ElGamalSK setup(int nc, int kappa) {
        int bitlength = kappa * 8;
//        BulletinBoardV2_0 bb = athenaFactory.getBulletinBoard();
        BulletinBoard bb = BulletinBoard.getInstance(); // TODO: RePLACE WITH ABOVE WHEN BB IS DONE!
        Random random = athenaFactory.getRandom();

        // Get the group
        Group group = this.getGroup(bitlength, random);

        // Create elgamal and generate keys
        ElGamalSK sk = this.getElGamalSK(CONSTANTS.TALLIER_INDEX, group, random); // Dependent on the strategy this will be either the full sk or a share of it.
        ElGamalPK pk = this.getElGamalPK(sk); // TODO: should this be pk or h_i ?
        Sigma1Proof rho = this.proveKey(pk, sk, random, kappa);

        //this.elgamalWithLookUpTable = new Elgamal(group, nc, random);

        // mb, mc is upper-bound by a polynomial in the security parameter.
        // TODO: Should these be updated
        int mb = 1024; // TODO: look at the ElGamal test and find a
        BigInteger mc = BigInteger.valueOf(1024);

        List<List<BigInteger>> generators = GENERATOR.generateRangeProofGenerators(pk, nc);
        List<BigInteger> g_vector_vote = generators.get(0);
        List<BigInteger> h_vector_vote = generators.get(1);


        bb.publishNumberOfCandidates(nc);
        bb.publish_G_VectorVote(g_vector_vote); // TODO: compute on bulletin board when the pk is constructed
        bb.publish_H_VectorVote(h_vector_vote); // TODO: compute on bulletin board when the pk is constructed

        PK_Vector pkv = new PK_Vector(pk, rho); // TODO: Proof of full pk vs proof of public key share h_i? Should this proof be a list of proofs of h_i?
        bb.publishPKV(pkv);

        return sk;
    }

    @Override
    public ElGamalSK getElGamalSK(int i, Group group, Random random) {
        return Elgamal.generateSK(group, random);
    }

    @Override
    public ElGamalPK getElGamalPK(ElGamalSK sk) {
        return sk.pk; // TODO: retrieve pk/pkv from the bulletin board instead?
    }

    @Override
    public Sigma1Proof proveKey(ElGamalPK pk, ElGamalSK sk, Random random, int kappa) {
        Sigma1 sigma1 = athenaFactory.getSigma1();
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
    public BigInteger decrypt(Ciphertext c, ElGamalSK sk) {
        return Elgamal.decrypt(c, sk);
    }




}
