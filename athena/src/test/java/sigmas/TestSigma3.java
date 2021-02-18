package sigmas;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.Gen;
import project.athena.Sigma3;
import project.dao.PK_SK_FRAKM;
import project.dao.Randomness;
import project.dao.sigma3.DecryptionProof;
import project.dao.sigma3.PublicInfoSigma3;
import project.elgamal.CipherText;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.Factory;
import project.factory.MainFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static org.junit.Assert.assertTrue;

@Tag("TestsSigma3")
@DisplayName("Test Sigma3")
public class TestSigma3 {
    private final int kappa = CONSTANTS.KAPPA;
    private Sigma3 sigma3;
    private PublicInfoSigma3 info;
    private ElGamalSK sk;


    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        ElGamal elGamal = factory.getElgamal();
        ElGamalPK pk = factory.getPK();
        sk = factory.getSK();
        sigma3 = new Sigma3(factory.getHash());

        BigInteger msg_m = new BigInteger("491");


        CipherText cipherText = elGamal.encrypt(msg_m, pk);
        info = new PublicInfoSigma3(pk, cipherText, msg_m);
    }


    @Test
    void TestSigma3_checkPart1() {
        DecryptionProof decryptionProof = sigma3.proveDecryption(info, sk, kappa);
        // for check part1
        BigInteger g = info.pk.getGroup().getG();
        BigInteger p = info.pk.getGroup().getP();
        BigInteger h = info.pk.getH();
        BigInteger a = decryptionProof.a;

        // for check part2
        BigInteger c1 = info.cipherText.c1;
        BigInteger c2 = info.cipherText.c2;
        BigInteger z = c2.multiply(info.plainText.modInverse(p)).mod(p); //c1^sk
        BigInteger b = decryptionProof.b;

        BigInteger c = sigma3.hash(a, b, g, h, z, c1, c2);
        BigInteger r = decryptionProof.r;

        boolean check1 = sigma3.checkPart1(g, r, a, h, c, p);
        assertTrue("Verify check1", check1);

    }

    @Test
    void TestSigma3_checkPart2() {
        DecryptionProof decryptionProof = sigma3.proveDecryption(info, sk, kappa);
        // for check part1
        BigInteger g = info.pk.getGroup().getG();
        BigInteger p = info.pk.getGroup().getP();
        BigInteger h = info.pk.getH();
        BigInteger a = decryptionProof.a;

        // for check part2
        BigInteger c1 = info.cipherText.c1;
        BigInteger c2 = info.cipherText.c2;
        BigInteger z = c2.multiply(info.plainText.modInverse(p)).mod(p); //c1^sk
        BigInteger b = decryptionProof.b;

        BigInteger c = sigma3.hash(a, b, g, h, z, c1, c2);
        BigInteger r = decryptionProof.r;

        boolean check2 = sigma3.checkPart2(c1, r, b, z, c,p);
        assertTrue("Verify check2", check2);
    }



    @Test
    void TestSigma3() {
        DecryptionProof decryptionProof = sigma3.proveDecryption(info, sk, kappa);
        boolean verification = sigma3.verifyDecryption(info, decryptionProof, kappa);
        assertTrue("Should be 1", verification);

    }

    @Test
    void TestSigma3New() {
        DecryptionProof decryptionProof = sigma3.proveDecryptionNew(info.cipherText, info.plainText, sk, kappa);
        boolean verification = sigma3.verifyDecryptionNew(info.cipherText, info.plainText, sk.getPK(), decryptionProof, kappa);
        assertTrue("Should be 1", verification);

    }

}
