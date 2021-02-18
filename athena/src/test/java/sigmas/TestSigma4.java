package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.Sigma4;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.CipherText;
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

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        sigma4 = new Sigma4(factory.getHash());
        sk = factory.getSK();
        pk = factory.getPK();

    }


    /**
     * START HERE FUCKERSS!!!!!!!!!!
     */
    @Test
    void TestSigma4_Tally_single() {
        //(c1,c2) = (b1^n,b2^n)
        BigInteger p = pk.getGroup().getP();

        BigInteger c1 = BigInteger.valueOf(11);
        BigInteger c2 = BigInteger.TWO;

        int nonce_n = new Random(CONSTANTS.RANDOM_SEED).nextInt();
        CipherText b0 = new CipherText(c1, c2);
        CipherText c0 = b0.modPow(BigInteger.valueOf(nonce_n), p); // modpow(n,p)


        List<CipherText> c_list = Arrays.asList(c0);
        List<CipherText> b_list = Arrays.asList(b0);
        Sigma4Proof omega = sigma4.proveCombination(sk, c_list, b_list, nonce_n,kappa);
        boolean verification = sigma4.verifyCombination(pk, c_list, b_list, omega, kappa);
        assertTrue("VerComb(...)=1", verification);

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
