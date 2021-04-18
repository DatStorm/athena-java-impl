package cs.au.athena.athena.strategy;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.AthenaCommon;

import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.Randomness;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma1.ProveKeyInfo;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.generator.Gen;
import cs.au.athena.generator.Generator;
import cs.au.athena.generator.MockGenerator;
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
    public ElGamalSK getElGamalSK(int i, Group group, Random random) {
        return Elgamal.generateSK(group, random);
    }

    @Override
    public ElGamalPK getElGamalPK(ElGamalSK sk) {
        return sk.pk; // TODO: retrieve pk/pkv from the bulletin board instead?
    }

    @Override
    public ProveKeyInfo proveKey(ElGamalPK pk, ElGamalSK sk, Randomness r, int kappa) {
        Sigma1 sigma1 = athenaFactory.getSigma1();
        return sigma1.ProveKey(pk, sk, r, kappa);
    }

    @Override
    public boolean verifyKey(ElGamalPK pk, ProveKeyInfo rho, int kappa) {
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
