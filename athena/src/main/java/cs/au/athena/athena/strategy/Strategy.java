package cs.au.athena.athena.strategy;

import cs.au.athena.athena.BulletinBoard;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.Randomness;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.sigma1.ProveKeyInfo;
import cs.au.athena.dao.sigma1.PublicInfoSigma1;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;
import cs.au.athena.generator.Generator;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public interface Strategy {

    /**
     * Setup / Key generation
     */
    Generator getGenerator(Random random, int nc, int bitlength);

    /**
     * ProveKey_{SIGMA_1} & VerifyKey_{SIGMA_1}
     */
    ProveKeyInfo proveKey(PublicInfoSigma1 publicInfo, ElGamalSK sk, Randomness r, int kappa);
    boolean verifyKey(PublicInfoSigma1 publicInfoSigma1, ProveKeyInfo rho, int kappa);

    /**
     * ProveDec_{SIGMA_3} & VerifyDec_{SIGMA_3}
     */
    Sigma3Proof proveDecryption(Ciphertext c, BigInteger M, ElGamalSK sk, int kappa);
    boolean verifyDecryption(Ciphertext c, BigInteger M, ElGamalPK pk, Sigma3Proof phi, int kappa);

    /**
     * ProveComb_{SIGMA_4} & VerifyComb_{SIGMA_4}
     */
    Sigma4Proof proveCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, BigInteger nonce_n, ElGamalSK sk, int kappa);
    boolean verifyCombination(List<Ciphertext> listOfCombinedCiphertexts, List<Ciphertext> listCiphertexts, Sigma4Proof omega, ElGamalPK pk, int kappa);


    /**
     * ProveMix_{M} & VerifyMix_{M}
     */
    // TODO: proveMix, what should it return (mixedBallots, proof) or proof
    MixedBallotsAndProof proveMix(List<MixBallot> ballots, ElGamalPK pk, int kappa);

    // TODO: verifyMix


    /**
     * OTHER important stuff...
     */
    Ciphertext homoCombination(Ciphertext c, BigInteger nonce, Group group);


    BigInteger decrypt(Ciphertext c, ElGamalSK sk);




}
