package cs.au.athena.mixnet;

import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.mixnet.*;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.Factory;
import cs.au.athena.factory.MainFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitPlatform.class)
@Tag("TestsMixnets")
@DisplayName("Test Mixnet")
public class TestMixnet {
    private int kappa = CONSTANTS.KAPPA;

    
    private Mixnet mixnet;
    private Elgamal elgamal;
    private ElGamalPK pk;
    private ElGamalSK sk;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        elgamal = factory.getElgamal();
        pk = factory.getPK();
        sk = factory.getSK();
        Random random = factory.getRandom();

        mixnet = new Mixnet(elgamal, pk, random);

    }


    @Test
    void TestMixBallot_Multiply() {
        int a = 2;
        int b = 3;
        int c = a + b;
        Ciphertext cipher_1 = elgamal.exponentialEncrypt(BigInteger.valueOf(a), pk);
        Ciphertext cipher_2 = elgamal.exponentialEncrypt(BigInteger.valueOf(b), pk);

        BigInteger g = pk.getGroup().getG();


        int va = 10;
        int vb = 20;
        int vc = va + vb;
        Ciphertext v1 = elgamal.exponentialEncrypt(BigInteger.valueOf(va), pk);
        Ciphertext v2 = elgamal.exponentialEncrypt(BigInteger.valueOf(vb), pk);
        // mb1 = (c1 = Enc(1),c2= Enc(v))
        MixBallot mb1 = new MixBallot(cipher_1, v1);
        MixBallot mb2 = new MixBallot(cipher_2, v2);

        BigInteger p = pk.getGroup().getP();
        MixBallot mult = mb1.multiply(mb2,p);

        BigInteger dec_c1 = elgamal.decrypt(mult.getCombinedCredential(), sk);
        assertEquals("should be ??", g.modPow(BigInteger.valueOf(c),p), dec_c1);
        
        BigInteger dec_c2 = elgamal.decrypt(mult.getEncryptedVote(), sk);
        assertEquals("should be ??", g.modPow(BigInteger.valueOf(vc),p), dec_c2);
    }

    @Test
    void TestMixnet() {
        Ciphertext cipher_1 = elgamal.exponentialEncrypt(BigInteger.valueOf(1), pk);

        Ciphertext v1 = elgamal.exponentialEncrypt(BigInteger.valueOf(100), pk);
        // mb1 = (c1 = Enc(1),c2= Enc(v))
        MixBallot mb1 = new MixBallot(cipher_1, v1);

        Ciphertext v2 = elgamal.exponentialEncrypt(BigInteger.valueOf(101), pk);
        MixBallot mb2 = new MixBallot(cipher_1, v2);

        Ciphertext v3 = elgamal.exponentialEncrypt(BigInteger.valueOf(102), pk);
        MixBallot mb3 = new MixBallot(cipher_1, v3);
//        CipherText b4 = cs.au.cs.au.athena.athena.elgamal.encrypt(BigInteger.valueOf(103),pk);
//        MixnetStatement stmt = new MixnetStatement(Arrays.asList(b1,b2,b3,b4));


        List<MixBallot> ballots = Arrays.asList(mb1, mb2, mb3);

        MixedBallotsAndProof pair = mixnet.mixAndProveMix(ballots, pk, kappa);
        MixStatement statement = new MixStatement(ballots, pair.mixedBallots);

        boolean verification = mixnet.verify(statement, pair.mixProof, pk, kappa);

        assertTrue("Should return 1: " + verification, verification);
    }
}
