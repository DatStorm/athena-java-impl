package cs.au.athena.athena.strategy;

import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.Randomness;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.sigma1.ProveKeyInfo;
import cs.au.athena.dao.sigma1.PublicInfoSigma1;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.generator.Generator;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class DistributedStrategy implements Strategy {

    AthenaFactory athenaFactory;
    public DistributedStrategy(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
    }



    @Override
    public Generator getGenerator(Random random, int nc, int bitlength) {
        return null;
    }

    @Override
    public ProveKeyInfo proveKey(PublicInfoSigma1 publicInfo, ElGamalSK sk, Randomness r, int kappa) {
        return null;
    }

    @Override
    public boolean verifyKey(PublicInfoSigma1 publicInfoSigma1, ProveKeyInfo rho, int kappa) {
        return false;
    }

    @Override
    public Sigma3Proof proveDecryption(Ciphertext c, BigInteger M, ElGamalSK sk, int kappa) {
        return null;
    }

    @Override
    public boolean verifyDecryption(Ciphertext c, BigInteger M, ElGamalPK pk, Sigma3Proof phi, int kappa) {
        return false;
    }

    @Override
    public Sigma4Proof proveCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, BigInteger nonce_n, ElGamalSK sk, int kappa) {
        return null;
    }

    @Override
    public boolean verifyCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, Sigma4Proof omega, ElGamalPK pk, int kappa) {
        return false;
    }

    @Override
    public MixedBallotsAndProof proveMix(List<MixBallot> ballots, ElGamalPK pk, int kappa) {
        return null;
    }

    @Override
    public Ciphertext homoCombination(Ciphertext c, BigInteger nonce, Group group) {
        return null;
    }

    @Override
    public BigInteger decrypt(Ciphertext c, ElGamalSK sk) {
        return null;
    }
}
