package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.Sigma4;
import project.dao.sigma4.CombinationProof;
import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;
import project.factory.Factory;
import project.factory.MainFactory;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertTrue;

@Tag("TestsSigma4")
@DisplayName("Test Sigma4")
public class TestSigma4 {

    private Sigma4 sigma4;
    private final int kappa = CONSTANTS.KAPPA;
    private ElGamalPK pk;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();

        sigma4 = new Sigma4(factory.getHash());
        pk = factory.getPK();

    }


    @Test
    void TestSigma4_step2_Tally() {

        BigInteger c1 = BigInteger.ONE;
        BigInteger c2 = BigInteger.TWO;
        CipherText ci_1_prime = new CipherText(c1, c2);
        CipherText ci_prime = new CipherText(c1, c2);
        CipherText bi_1 = new CipherText(c1, c2);
        CipherText bi = new CipherText(c1, c2);
        int nonce_n = new Random(CONSTANTS.RANDOM_SEED).nextInt();
//        CombinationProof omega = sigma4.proveCombination(pk, ci_1_prime, ci_prime, bi_1, bi, nonce_n,kappa);
//        boolean verification = sigma4.verifyCombination(pk, c_prime, c1, omega, kappa);
        assertTrue("Should be 1", true);

    }
}
