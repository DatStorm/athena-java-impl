package cs.au.athena.athena.strategy;

import cs.au.athena.athena.AthenaCommon;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.Randomness;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.mixnet.MixStruct;
import cs.au.athena.dao.sigma1.ProveKeyInfo;
import cs.au.athena.dao.sigma1.PublicInfoSigma1;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.generator.Gen;
import cs.au.athena.generator.Generator;
import cs.au.athena.generator.MockGenerator;
import cs.au.athena.mixnet.Mixnet;
import cs.au.athena.sigma.Sigma4;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class SingleTallierStrategy implements Strategy {

    AthenaFactory athenaFactory;
    public SingleTallierStrategy(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
    }


    @Override
    public Generator getGenerator(Random random, int nc, int bitlength) {
        Generator gen = new Gen(random, nc, bitlength);
        gen = new MockGenerator(random, nc, bitlength); // TODO: comment out if we want the generate "fresh" group, i.e. primes p and q
        return gen;
    }



    @Override
    public ProveKeyInfo proveKey(PublicInfoSigma1 publicInfo, ElGamalSK sk, Randomness r, int kappa) {
        return athenaFactory.getSigma1().ProveKey(publicInfo, sk, r, kappa);
    }

    @Override
    public boolean verifyKey(PublicInfoSigma1 publicInfoSigma1, ProveKeyInfo rho, int kappa) {
        return athenaFactory.getSigma1().VerifyKey(publicInfoSigma1, rho, kappa);
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
        // TODO: Wait for turn

        //Mix
        Mixnet mixnet = athenaFactory.getMixnet();
        return mixnet.mixAndProveMix(ballots, pk, kappa);

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
