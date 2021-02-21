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
import project.factory.Factory;
import project.factory.MainFactory;
import project.mixnet.Mixnet;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

@Tag("TestsMixnets")
@DisplayName("Test Mixnet")
public class TestMixnet {

    private Mixnet mixnet;
    private ElGamal elgamal;
    private ElGamalPK pk;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        mixnet = new Mixnet(factory);
        elgamal = factory.getElgamal();
        pk = factory.getPK();

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
        MixnetStatement stmt = new MixnetStatement(Arrays.asList(mb1, mb2, mb3));
        MixnetProof proof = mixnet.proveMix(stmt);
        boolean verification = mixnet.verify(proof);

        assertTrue("Should return 1", verification);
    }
}
