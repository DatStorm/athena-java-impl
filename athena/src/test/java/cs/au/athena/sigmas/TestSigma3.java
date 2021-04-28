package cs.au.athena.sigmas;

import cs.au.athena.CONSTANTS;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.*;
import cs.au.athena.sigma.Sigma3;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma3.Sigma3Statement;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.Factory;
import cs.au.athena.factory.MainFactory;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertTrue;

@Tag("TestsSigma3")
@DisplayName("Test Sigma3")
public class TestSigma3 {
    private final int kappa = CONSTANTS.KAPPA;
    private Sigma3 sigma3;
    private Sigma3Statement statement;
    private ElGamalSK sk;
    private Ciphertext cipher;
    private BigInteger plain_msg_m;



    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        ElGamal elGamal = factory.getElgamal();
        ElGamalPK pk = factory.getPK();
        sk = factory.getSK();
        sigma3 = new Sigma3();

        // 41 Not a group element in G = Z_p^* , G = {g^i | i in Zq}
        // g^41 is though
        plain_msg_m = new BigInteger("41");
        cipher = elGamal.exponentialEncrypt(plain_msg_m, pk);
        statement = Sigma3.createDecryptionStatement(cipher, plain_msg_m, pk);
    }



    @Test
    void TestSigma3() {
        BigInteger g = sk.pk.group.g;
        BigInteger p = sk.pk.group.p;
        BigInteger g_raised_to_plain = g.modPow(this.plain_msg_m,p);
        Sigma3Proof sigma3Proof = sigma3.proveDecryption(cipher, g_raised_to_plain, sk, kappa);
        boolean verification = sigma3.verifyDecryption(cipher, g_raised_to_plain, sigma3Proof, sk.getPK(), kappa);
        MatcherAssert.assertThat("VerDec(...)=1", verification, is(true));
    }


}
