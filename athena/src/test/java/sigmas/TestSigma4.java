package sigmas;


import org.junit.jupiter.api.*;
import project.CONSTANTS;
import project.sigma.Sigma4;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.Factory;
import project.factory.MainFactory;

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
     * Test equivalent to ProveComb of Tally step3
     */
    @Test
    void TestSigma4_Tally_single() {
        //(c1,c2) = (b1^n,b2^n)
        BigInteger p = pk.getGroup().getP();

        BigInteger c1 = BigInteger.valueOf(6);
        BigInteger c2 = BigInteger.valueOf(7);

//        int nonce_n = new Random(CONSTANTS.RANDOM_SEED).nextInt();
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

//        int nonce_n = new Random(CONSTANTS.RANDOM_SEED).nextInt();
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



    /**
    * Test equivalent to ProveComb of Tally step2
    **/
    @Test
    void TestSigma4_Tally_two_ciphertexts() {
        //(c1,c2) = (b1^n,b2^n)
        BigInteger p = pk.getGroup().getP();

        BigInteger c1 = BigInteger.valueOf(3);
        BigInteger c2 = BigInteger.valueOf(4);

        BigInteger c1_extra = BigInteger.valueOf(6);
        BigInteger c2_extra = BigInteger.valueOf(7);

//        int nonce_n = new Random(CONSTANTS.RANDOM_SEED).nextInt();
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

    //        int nonce_n = new Random(CONSTANTS.RANDOM_SEED).nextInt();
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
