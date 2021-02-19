package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.Sigma4;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.CipherText;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.Factory;
import project.factory.MainFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertTrue;

@Tag("TestsSigma4")
@DisplayName("Test Sigma4")
public class TestSigma4 {
    private final int kappa = CONSTANTS.KAPPA;

    private Sigma4 sigma4;
    private ElGamalSK sk;
    private ElGamalPK pk;
    private ElGamal elgamal;


    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        sigma4 = new Sigma4(factory.getHash());
        elgamal = factory.getElgamal();
        sk = factory.getSK();
        pk = factory.getPK();

    }


    /**
     * START HERE FUCKERS!!!!!!!!!!
     */
    @Test
    void TestSigma4_Tally_single() {
        //(c1,c2) = (b1^n,b2^n)
        BigInteger p = pk.getGroup().getP();

        BigInteger c1 = BigInteger.valueOf(3);
        BigInteger c2 = BigInteger.valueOf(4);

//        int nonce_n = new Random(CONSTANTS.RANDOM_SEED).nextInt();
        int nonce_n = 4;
        CipherText origin = new CipherText(c1, c2);
        CipherText combination = origin.modPow(BigInteger.valueOf(nonce_n), p); // modpow(n,p)

        List<CipherText> origin_list = Arrays.asList(origin);
        List<CipherText> combination_list = Arrays.asList(combination);
        Sigma4Proof omega = sigma4.proveCombination(sk, combination_list, origin_list, nonce_n, kappa);
        boolean verification = sigma4.verifyCombination(pk, combination_list, origin_list, omega, kappa);
        assertTrue("VerComb(...)=1", verification);
    }


    @Test
    void TestSigma4_Tally_step3_proveComb() {


        int n = 3;

        // c1
        CipherText c1 = elgamal.encrypt(new BigInteger("22"), pk);
//        BigInteger plain = elgamal.decrypt(c1, sk);
//        System.out.println("1=="+ plain);

        // homo combination n times of c1
        CipherText c_prime = new CipherText(c1.c1.pow(n), c1.c2.pow(n));
//        CipherText c_prime_2 = c1.modPow(BigInteger.valueOf(n), pk.getGroup().getP());
//        System.out.println("1=?"+ elgamal.decrypt(c_prime_2, sk));

        List<CipherText> c_list = Arrays.asList(c_prime, c1);
        Sigma4Proof omega = sigma4.proveCombination(sk, c_list, n, kappa);
//        boolean verification = sigma4.verifyCombination(pk, combination_list, origin_list, omega, kappa);
//        assertTrue("VerComb(...)=1", verification);

    }


    @Test
    void TestSigma4_step2_Tally() {
        //(c1,c2) = (b1^n,b2^n)

        BigInteger c1 = BigInteger.ONE;
//        BigInteger c2 = BigInteger.TWO;
//
//        CipherText c0 = new CipherText(c1, c2);
//        CipherText c1 = new CipherText(c1, c2);
//
//        CipherText b0 = new CipherText(c1, c2);
//        CipherText b1 = new CipherText(c1, c2);
//        int nonce_n = new Random(CONSTANTS.RANDOM_SEED).nextInt();
//
//        List<CipherText> c_list = Arrays.asList(c0, c1);
//        List<CipherText> b_list = Arrays.asList(b0, b1);
//        Sigma4Proof omega = sigma4.proveCombination(sk, c_list, b_list, nonce_n,kappa);
//        boolean verification = sigma4.verifyCombination(pk, c_list, b_list, omega, kappa);
//        assertTrue("VerComb(...)=1", verification);

    }
}
