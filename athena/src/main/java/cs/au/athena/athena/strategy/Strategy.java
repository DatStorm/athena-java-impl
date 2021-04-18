package cs.au.athena.athena.strategy;

import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.Randomness;
import cs.au.athena.dao.athena.ElectionSetup;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.*;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public interface Strategy {

    //TODO: Remove random from param. Should be given to constructor.
    Group getGroup(int kappa, Random random);

    //TODO: Move nc to BB
    ElGamalSK setup(int tallierIndex, int nc, int kappa);
    ElGamalSK getElGamalSK(int tallierIndex, Group group, Random random);
    ElGamalPK getElGamalPK(ElGamalSK sk);
    /**
     * ProveKey_{SIGMA_1} & VerifyKey_{SIGMA_1}
     */
    Sigma1Proof proveKey(ElGamalPK pk, ElGamalSK sk, int kappa);
    boolean verifyKey(ElGamalPK pk, Sigma1Proof rho, int kappa);

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
    // TODO: rename to mixAndProveMix
    MixedBallotsAndProof proveMix(List<MixBallot> ballots, ElGamalPK pk, int kappa);
    boolean verifyMix(MixStatement statement, MixProof proof, ElGamalPK pk, int kappa);

    /**
     * OTHER important stuff...
     */
    Ciphertext homoCombination(Ciphertext c, BigInteger nonce, Group group);


    BigInteger decrypt(Ciphertext c, ElGamalSK sk);


}
