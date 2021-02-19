package sigmas;

import org.junit.jupiter.api.*;
import project.CONSTANTS;
import project.athena.Sigma3;
import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma3.Sigma3Statement;
import project.elgamal.CipherText;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.Factory;
import project.factory.MainFactory;

import java.math.BigInteger;

import static org.junit.Assert.assertTrue;

@Tag("TestsSigma3")
@DisplayName("Test Sigma3")
public class TestSigma3 {
    private final int kappa = CONSTANTS.KAPPA;
    private Sigma3 sigma3;
    private Sigma3Statement statement;
    private ElGamalSK sk;
    private CipherText cipher;
    private BigInteger plain_msg_m;



    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        ElGamal elGamal = factory.getElgamal();
        ElGamalPK pk = factory.getPK();
        sk = factory.getSK();
        sigma3 = new Sigma3(factory.getHash());

        plain_msg_m = new BigInteger("491");

        cipher = elGamal.encrypt(plain_msg_m, pk);
        statement = sigma3.createStatement(pk, cipher, plain_msg_m);
    }


    @Test
    void TestSigma3_checkPart1() {
        // ProveDec s1 = ProveDec(...)'
        Sigma3Proof proof = sigma3.proveDecryption(cipher, plain_msg_m, sk, kappa);
        BigInteger c = sigma3.hash(proof.a, proof.b, statement.alpha, statement.beta, statement.alpha_base, statement.beta_base, statement.beta_base);
        boolean check1 = sigma3.checkPart1(statement.alpha_base, proof.r, proof.a, statement.alpha, c, statement.group.p);
        assertTrue("Verify check1", check1);

    }

    @Test
    void TestSigma3_checkPart2() {
        Sigma3Proof proof = sigma3.proveDecryption(cipher, plain_msg_m,sk, kappa);
        BigInteger c = sigma3.hash(proof.a, proof.b, statement.alpha, statement.beta, statement.alpha_base, statement.beta_base, statement.beta_base);
        boolean check2 = sigma3.checkPart2(statement.beta_base, proof.r, proof.b, statement.beta,  c, statement.group.p);
        assertTrue("Verify check2", check2);
    }


    @RepeatedTest(10)
    void TestSigma3() {
        Sigma3Proof sigma3Proof = sigma3.proveDecryption(cipher, plain_msg_m,sk, kappa);
        boolean verification = sigma3.verifyDecryption(cipher, plain_msg_m, sk.getPK(), sigma3Proof, kappa);
        assertTrue("VerDec(...)=1", verification);
    }

}
