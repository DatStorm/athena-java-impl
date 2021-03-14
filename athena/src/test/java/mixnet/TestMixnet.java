package mixnet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.dao.mixnet.*;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.Factory;
import project.factory.MainFactory;
import project.mixnet.Mixnet;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@Tag("TestsMixnets")
@DisplayName("Test Mixnet")
public class TestMixnet {
    private int kappa = CONSTANTS.KAPPA;

    
    private Mixnet mixnet;
    private ElGamal elgamal;
    private ElGamalPK pk;
    private ElGamalSK sk;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        elgamal = factory.getElgamal();
        pk = factory.getPK();
        sk = factory.getSK();
        MessageDigest hash = factory.getHash();
        Random random = factory.getRandom();

        mixnet = new Mixnet(hash, elgamal, pk, random);

    }


    @Test
    void TestMixBallot_Multiply() {
        int a = 2;
        int b = 3;
        int c = a + b;
        Ciphertext cipher_1 = elgamal.encrypt(BigInteger.valueOf(a), pk);
        Ciphertext cipher_2 = elgamal.encrypt(BigInteger.valueOf(b), pk);

        BigInteger g = pk.getGroup().getG();


        int va = 10;
        int vb = 20;
        int vc = va + vb;
        Ciphertext v1 = elgamal.encrypt(BigInteger.valueOf(va), pk);
        Ciphertext v2 = elgamal.encrypt(BigInteger.valueOf(vb), pk);
        // mb1 = (c1 = Enc(1),c2= Enc(v))
        MixBallot mb1 = new MixBallot(cipher_1, v1);
        MixBallot mb2 = new MixBallot(cipher_2, v2);

        BigInteger p = pk.getGroup().getP();
        MixBallot mult = mb1.multiply(mb2,p);

        BigInteger dec_c1 = elgamal.decrypt(mult.getC1(),sk);
        assertEquals("should be ??", g.modPow(BigInteger.valueOf(c),p), dec_c1);
        
        BigInteger dec_c2 = elgamal.decrypt(mult.getC2(),sk);
        assertEquals("should be ??", g.modPow(BigInteger.valueOf(vc),p), dec_c2);
    }

    @Test
    void TestMixnet() {
        Ciphertext cipher_1 = elgamal.encrypt(BigInteger.valueOf(1), pk);

        Ciphertext v1 = elgamal.encrypt(BigInteger.valueOf(100), pk);
        // mb1 = (c1 = Enc(1),c2= Enc(v))
        MixBallot mb1 = new MixBallot(cipher_1, v1);

        Ciphertext v2 = elgamal.encrypt(BigInteger.valueOf(101), pk);
        MixBallot mb2 = new MixBallot(cipher_1, v2);

        Ciphertext v3 = elgamal.encrypt(BigInteger.valueOf(102), pk);
        MixBallot mb3 = new MixBallot(cipher_1, v3);
//        CipherText b4 = elgamal.encrypt(BigInteger.valueOf(103),pk);
//        MixnetStatement stmt = new MixnetStatement(Arrays.asList(b1,b2,b3,b4));


        List<MixBallot> ballots = Arrays.asList(mb1, mb2, mb3);
        MixStruct mixStruct = mixnet.mix(ballots);

        MixStatement statement = new MixStatement(ballots, mixStruct.mixedBallots);
        MixProof proof = mixnet.proveMix(statement, mixStruct.secret, kappa);

        boolean verification = mixnet.verify(statement, proof, kappa);

        assertTrue("Should return 1: " + verification, verification);
    }
}
