package cs.au.athena.sigma.mixnet;

import cs.au.athena.UTIL;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.*;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.mixnet.*;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.Factory;
import cs.au.athena.factory.MainFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitPlatform.class)
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
        Random random = factory.getRandom();

        mixnet = new Mixnet(random);

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

        MixBallot mult = mb1.multiply(mb2, pk.group);
        BigInteger p = pk.group.p;

        BigInteger dec_c1 = ElGamal.decrypt(mult.getCombinedCredential(), sk);
        assertEquals("should be ??", g.modPow(BigInteger.valueOf(c),p), dec_c1);
        
        BigInteger dec_c2 = ElGamal.decrypt(mult.getEncryptedVote(), sk);
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

        boolean verification = Mixnet.verify(statement, pair.mixProof, pk, kappa);

        Assertions.assertTrue(verification, "Should return 1: " + verification);
    }



    @Test
    void TestMixAndProveMixWithXBallots() {
//        Execution time in seconds : 			?
//        int numBallots = 10; // 69
//        int numBallots = 20; // 141
//        int numBallots = 50; // 375
//        int numBallots = 100;// 828
//        int numBallots = 200;// 2014
        int numBallots = 400; // ?

        Ciphertext c1 = new Ciphertext(new BigInteger("10000"),new BigInteger("20000") );
        Ciphertext c2 = new Ciphertext(new BigInteger("10000"),new BigInteger("20000") );

        /***********/
        long startTime = System.nanoTime();

        Mixnet mixnet = new Mixnet();
        List<MixBallot> mixBallots = IntStream.rangeClosed(1,numBallots).mapToObj((i) -> new MixBallot(c1, c2)).collect(Collectors.toList());

        MixedBallotsAndProof mixedBallotsAndProof = mixnet.mixAndProveMix(mixBallots, pk, kappa);

        MixStatement smnt = new MixStatement(mixBallots, mixedBallotsAndProof.mixedBallots);

        boolean verification = Mixnet.verify(smnt, mixedBallotsAndProof.mixProof, pk, kappa);
        long endTime = System.nanoTime();
        /***********/

        UTIL.printEvalMetrics(String.format("Mixnet with %d took: ", numBallots), startTime, endTime);


        MatcherAssert.assertThat("Assert true.", verification, is(true));
    }
}
