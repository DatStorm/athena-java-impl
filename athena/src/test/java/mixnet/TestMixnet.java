package mixnet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixnetProof;
import project.dao.mixnet.MixnetStatement;
import project.elgamal.CipherText;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.Factory;
import project.factory.MainFactory;
import project.mixnet.Mixnet;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@Tag("TestsMixnets")
@DisplayName("Test Mixnet")
public class TestMixnet {

    private Mixnet mixnet;
    private ElGamal elgamal;
    private ElGamalPK pk;
    private ElGamalSK sk;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        mixnet = new Mixnet(factory);
        elgamal = factory.getElgamal();
        pk = factory.getPK();
        sk = factory.getSK();

    }


    @Test
    void TestMixBallot_Multiply() {
        int a = 2;
        int b = 3;
        int c = a * b;
        CipherText cipher_1 = elgamal.encrypt(BigInteger.valueOf(a), pk);
        CipherText cipher_2 = elgamal.encrypt(BigInteger.valueOf(b), pk);


        int va = 10;
        int vb = 20;
        int vc = va * vb;
        CipherText v1 = elgamal.encrypt(BigInteger.valueOf(va), pk);
        CipherText v2 = elgamal.encrypt(BigInteger.valueOf(vb), pk);
        // mb1 = (c1 = Enc(1),c2= Enc(v))
        MixBallot mb1 = new MixBallot(cipher_1, v1);
        MixBallot mb2 = new MixBallot(cipher_2, v2);

        MixBallot mult = mb1.multiply(mb2);

        BigInteger dec_c1 = elgamal.decrypt(mult.getC1(),sk);
        assertEquals("should be ??", BigInteger.valueOf(c), dec_c1);


        BigInteger dec_c2 = elgamal.decrypt(mult.getC2(),sk);
        assertEquals("should be ??", BigInteger.valueOf(vc), dec_c2);


    }

    @Test
    void TestMixnet() {
        CipherText cipher_1 = elgamal.encrypt(BigInteger.valueOf(1), pk);

        CipherText v1 = elgamal.encrypt(BigInteger.valueOf(100), pk);
        // mb1 = (c1 = Enc(1),c2= Enc(v))
        MixBallot mb1 = new MixBallot(cipher_1, v1);

        CipherText v2 = elgamal.encrypt(BigInteger.valueOf(101), pk);
        MixBallot mb2 = new MixBallot(cipher_1, v2);

        CipherText v3 = elgamal.encrypt(BigInteger.valueOf(102), pk);
        MixBallot mb3 = new MixBallot(cipher_1, v3);
//        CipherText b4 = elgamal.encrypt(BigInteger.valueOf(103),pk);
//        MixnetStatement stmt = new MixnetStatement(Arrays.asList(b1,b2,b3,b4));
        List<MixBallot> BcalList = Arrays.asList(mb1, mb2, mb3);
        MixnetStatement stmt = new MixnetStatement(BcalList);
        MixnetProof proof = mixnet.proveMix(stmt);
        boolean verification = mixnet.verify(BcalList, proof);

        assertTrue("Should return 1", verification);
    }
}
