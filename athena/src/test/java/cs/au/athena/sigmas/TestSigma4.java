package cs.au.athena.sigmas;


import org.junit.jupiter.api.*;
import cs.au.athena.CONSTANTS;
import cs.au.athena.sigma.Sigma4;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.Factory;
import cs.au.athena.factory.MainFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Tag("TestsSigma4")
@DisplayName("Test Sigma4")
public class TestSigma4 {
    private final int kappa = CONSTANTS.KAPPA;

    private Sigma4 sigma4;
    private ElGamalSK sk;
    private ElGamalPK pk;
    private Elgamal elgamal;


    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        sigma4 = new Sigma4();
        elgamal = factory.getElgamal();
        sk = factory.getSK();
        pk = factory.getPK();
    }


    /**
     * Test equivalent to ProveComb of Tally step3
     */
    @Test
    void TestSigma4_Tally_single() {
        //(c1,c2) = (b1^n,b2^n)
        BigInteger p = pk.getGroup().getP();

        BigInteger c1 = BigInteger.valueOf(6);
        BigInteger c2 = BigInteger.valueOf(7);

//        int nonce_n = new Random(cs.au.cs.au.athena.athena.CONSTANTS.RANDOM_SEED).nextInt();
        int nonce_n = 4;
        Ciphertext origin = new Ciphertext(c1, c2);
        BigInteger nonce_n_asBigInteger = BigInteger.valueOf(nonce_n);
        Ciphertext combination = origin.modPow(nonce_n_asBigInteger, p); // modpow(n,p)

        List<Ciphertext> origin_list = Arrays.asList(origin);
        List<Ciphertext> combination_list = Arrays.asList(combination);
        Sigma4Proof omega = sigma4.proveCombination(sk, combination_list, origin_list, nonce_n_asBigInteger, kappa);
        boolean verification = sigma4.verifyCombination(pk, combination_list, origin_list, omega, kappa);
        assertTrue("VerComb(...)=1", verification);
    }

    /**
     * Test equivalent to ProveComb of Tally step3 but combination is not the same as nonce 
     */
    @Test
    void TestSigma4_Tally_single_different_amount_of_homo_comb() {
        //(c1,c2) = (b1^n,b2^n)
        BigInteger p = pk.getGroup().getP();

        BigInteger c1 = BigInteger.valueOf(6);
        BigInteger c2 = BigInteger.valueOf(7);

//        int nonce_n = new Random(cs.au.cs.au.athena.athena.CONSTANTS.RANDOM_SEED).nextInt();
        int nonce_n = 4;
        int numberComb = 5;
        Ciphertext origin = new Ciphertext(c1, c2);
        Ciphertext combination = origin.modPow(BigInteger.valueOf(numberComb), p); // modpow(n,p)

        BigInteger nonce_n_asBigInteger = BigInteger.valueOf(nonce_n);

        List<Ciphertext> origin_list = Arrays.asList(origin);
        List<Ciphertext> combination_list = Arrays.asList(combination);
        Sigma4Proof omega = sigma4.proveCombination(sk, combination_list, origin_list, nonce_n_asBigInteger, kappa);
        boolean verification = sigma4.verifyCombination(pk, combination_list, origin_list, omega, kappa);
        assertFalse("VerComb(...)=0", verification);
    }



    /*********************************************
    * Test equivalent to ProveComb of Tally step2
    *
    * -------------------------------------------
    * -DO NOT RUN WITH LOW VALUES ELGAMAL VALUES-
    * -------------------------------------------
    *
    *********************************************/
    @Test
//    @RepeatedTest(100)
    @Disabled
    void TestSigma4_Tally_two_ciphertexts() {
        //(c1,c2) = (b1^n,b2^n)
        BigInteger p = pk.getGroup().getP();

        BigInteger c1 = BigInteger.valueOf(3);
        BigInteger c2 = BigInteger.valueOf(4);

        BigInteger c1_extra = BigInteger.valueOf(6);
        BigInteger c2_extra = BigInteger.valueOf(7);

//        int nonce_n = new Random(cs.au.cs.au.athena.athena.CONSTANTS.RANDOM_SEED).nextInt();
        int nonce_n = 4;
        Ciphertext origin = new Ciphertext(c1, c2);
        Ciphertext combination = origin.modPow(BigInteger.valueOf(nonce_n), p); // modpow(n,p)

        Ciphertext origin_extra = new Ciphertext(c1_extra, c2_extra);
        Ciphertext combination_extra = origin_extra.modPow(BigInteger.valueOf(nonce_n), p); // modpow(n,p)

        BigInteger nonce_n_asBigInteger = BigInteger.valueOf(nonce_n);


        List<Ciphertext> origin_list = Arrays.asList(origin, origin_extra);
        List<Ciphertext> combination_list = Arrays.asList(combination, combination_extra);
        Sigma4Proof omega = sigma4.proveCombination(sk, combination_list, origin_list, nonce_n_asBigInteger, kappa);
        boolean verification = sigma4.verifyCombination(pk, combination_list, origin_list, omega, kappa);
        assertTrue("VerComb(...)=1", verification);
    }

        /**
        * Test equivalent to ProveComb of Tally step2 but with different nonce usage between i-1 and i
        **/
        @Test
        void TestSigma4_Tally_two_ciphertexts_different_nonce() {
            //(c1,c2) = (b1^n,b2^n)
            BigInteger p = pk.getGroup().getP();

            BigInteger c1 = BigInteger.valueOf(3);
            BigInteger c2 = BigInteger.valueOf(4);

            BigInteger c1_extra = BigInteger.valueOf(6);
            BigInteger c2_extra = BigInteger.valueOf(7);

    //        int nonce_n = new Random(cs.au.cs.au.athena.athena.CONSTANTS.RANDOM_SEED).nextInt();
            int nonce_n = 4;
            int nonce_n_alt = 7;
            Ciphertext origin = new Ciphertext(c1, c2);
            Ciphertext combination = origin.modPow(BigInteger.valueOf(nonce_n), p); // modpow(n,p)

            Ciphertext origin_extra = new Ciphertext(c1_extra, c2_extra);
            Ciphertext combination_extra = origin_extra.modPow(BigInteger.valueOf(nonce_n_alt), p); // modpow(n,p)

            BigInteger nonce_n_asBigInteger = BigInteger.valueOf(nonce_n);


            List<Ciphertext> origin_list = Arrays.asList(origin, origin_extra);
            List<Ciphertext> combination_list = Arrays.asList(combination, combination_extra);
            Sigma4Proof omega = sigma4.proveCombination(sk, combination_list, origin_list, nonce_n_asBigInteger, kappa);
            boolean verification = sigma4.verifyCombination(pk, combination_list, origin_list, omega, kappa);
            assertFalse("VerComb(...)=0", verification);
        }




//
//    @Test
//    void TestSigma4_step2_Tally() {
//        //(c1,c2) = (b1^n,b2^n)
//
//        BigInteger c1 = BigInteger.ONE;
//        BigInteger c2 = BigInteger.TWO;
//
//        Ciphertext cipher0 = new Ciphertext(c1, c2);
//        Ciphertext cipher1 = new Ciphertext(c1, c2);
//
//        Ciphertext cipher_b0 = new Ciphertext(c1, c2);
//        Ciphertext cipher_b1 = new Ciphertext(c1, c2);
//        int nonce_n = new Random(cs.au.cs.au.athena.athena.CONSTANTS.RANDOM_SEED).nextInt();
//
//        List<Ciphertext> c_list = Arrays.asList(cipher0, cipher1);
//        List<Ciphertext> b_list = Arrays.asList(cipher_b0, cipher_b1);
//        Sigma4Proof omega = sigma4.proveCombination(sk, c_list, b_list, BigInteger.valueOf(nonce_n),kappa);
//        boolean verification = sigma4.verifyCombination(pk, c_list, b_list, omega, kappa);
//        assertTrue("VerComb(...)=1", verification);
//
//    }
}
