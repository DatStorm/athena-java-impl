package cs.au.athena.bulletproof;


import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.*;
import cs.au.athena.UTIL;
import cs.au.athena.dao.athena.UVector;
import cs.au.athena.dao.bulletproof.BulletproofExtensionStatement;
import cs.au.athena.dao.bulletproof.BulletproofProof;
import cs.au.athena.dao.bulletproof.BulletproofSecret;
import cs.au.athena.dao.bulletproof.BulletproofStatement;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.factory.Factory;
import cs.au.athena.factory.MainFactory;
import cs.au.athena.sigma.bulletproof.Bulletproof;
import cs.au.athena.sigma.bulletproof.PedersenCommitment;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("TestsBulletProof")
@DisplayName("Test BulletProof")
public class TestBulletProof {
    private ElGamalPK pk;
    private Bulletproof bulletproof;
    private Random random;

    private Group group;
    private BigInteger g;
    private BigInteger q;
    private BigInteger p;
    private BigInteger h;
    private UVector fakeUVector;


    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        random = factory.getRandom();
        pk = factory.getPK();
        group = pk.group;

        g = pk.getGroup().getG();
        p = pk.getGroup().getP();
        q = pk.getGroup().getQ();
        h = pk.getH();
        bulletproof = new Bulletproof( factory.getRandom());


        // As we are not in Athena, we do not have vector u. so just choose random values.
        Ciphertext fake = new Ciphertext(BigInteger.ONE, BigInteger.ONE);
        BigInteger fakeCnt = BigInteger.ONE;
        fakeUVector = new UVector(fake, fake, fake, fakeCnt);
    }

    @Test
    void TestSigma2GenerateRandomY() {
        Random rand = new Random(-3738502893943924564L);
        BigInteger y = UTIL.getRandomElement(BigInteger.ONE, q, rand);
        // gcd(y, q) = 1
        assertEquals(BigInteger.ONE, y.gcd(q));

    }

    //    @RepeatedTest(100)
    @Test
    void TestSigma2GenerateGVector() {
        int n = 10;
        List<BigInteger> g_vector = group.newGenerators(n, random);
        boolean isUnique = g_vector.stream().distinct().count() == g_vector.size();
        assertTrue(isUnique);
    }


    @Test
    void TestSigma2GenerateList() {
        int n = 5;

        BigInteger two = BigInteger.TWO;
        BigInteger order = BigInteger.valueOf(100L);
        List<BigInteger> list = bulletproof.generateList(two, n, order);
        assertArrayEquals("should be the same", Stream.of(1, 2, 4, 8, 16).map(BigInteger::valueOf).toArray(), list.toArray());

        BigInteger val = BigInteger.valueOf(5);
        BigInteger order2 = BigInteger.valueOf(100L);
        List<BigInteger> list2 = bulletproof.generateList(val, n, order2);
        assertArrayEquals("should be the same", Stream.of(1, 5, 25, 25, 25).map(BigInteger::valueOf).toArray(), list2.toArray());
    }

    @Test
    void TestSigma2PedersenCommit() {
        BigInteger order = BigInteger.valueOf(150);

        BigInteger _g = BigInteger.valueOf(2);
        BigInteger _m = BigInteger.valueOf(4); // 2^4 = 16

        BigInteger _h = BigInteger.valueOf(3);
        BigInteger _r = BigInteger.valueOf(2); // 3^2 = 9


        BigInteger com = PedersenCommitment.commit(_g, _m, _h, _r, order);

        assertEquals(com, BigInteger.valueOf(144));

        /*
         * Test mod in commit works.
         */
        BigInteger order2 = BigInteger.valueOf(100);
        BigInteger com2 = PedersenCommitment.commit(_g, _m, _h, _r, order2);

        assertNotEquals(com2, BigInteger.valueOf(144));
        assertEquals(com2, BigInteger.valueOf(44));

        /*
         * Test mod works when negative commits.
         */
    }

    

    @Test
    void TestSigma2BulletProof() {
        BigInteger m = BigInteger.valueOf(5);
        int n = 10;

        // \gamma \in Z_q =[0,q-1]
        BigInteger gamma = UTIL.getRandomElement(q, random);
        BigInteger V = PedersenCommitment.commit(g, m, h, gamma, p);

        List<BigInteger> g_vector = group.newGenerators(n, random);
        List<BigInteger> h_vector = group.newGenerators(n, random);


        BulletproofStatement stmnt = new BulletproofStatement.Builder()
                .setN(n)
                .setV(V) // g^v h^t
                .setPK(pk)
                .set_G_Vector(g_vector)
                .set_H_Vector(h_vector)
                .setUVector(fakeUVector)
                .build();

        BulletproofSecret secret = new BulletproofSecret(m, gamma);
        BulletproofProof proof = bulletproof.proveStatement(stmnt, secret);

        boolean verification = bulletproof.verifyStatement(stmnt, proof);

        assertTrue("Should return 1", verification);

    }

    @Test
    void TestSigma2BulletProofArbitraryRange() {
        // Choose [0;H<<q]
        BigInteger H = BigInteger.valueOf(102);
        BigInteger m = BigInteger.valueOf(31);
        BigInteger gamma = UTIL.getRandomElement(BigInteger.ZERO, q, random);
        BigInteger V = PedersenCommitment.commit(g, m, h, gamma, p);


        int n = Bulletproof.getN(H);
        List<BigInteger> g_vector = group.newGenerators(n, random);
        List<BigInteger> h_vector = group.newGenerators(n, random);

        BulletproofExtensionStatement stmnt = new BulletproofExtensionStatement(
                H,
                new BulletproofStatement.Builder()
                        .setN(Bulletproof.getN(H))
                        .setV(V) // g^v h^t
                        .setPK(pk)
                        .set_G_Vector(g_vector)
                        .set_H_Vector(h_vector)
                        .setUVector(fakeUVector)
                        .build()
        );

        BulletproofSecret secret = new BulletproofSecret(m, gamma);
        Pair<BulletproofProof, BulletproofProof> proofPair = bulletproof.proveStatementArbitraryRange(stmnt, secret);

        boolean verification = bulletproof.verifyStatementArbitraryRange(stmnt, proofPair);

        assertThat("Should be 1", verification, is(true));
    }

  

    @Test
    void TestSigma2BulletProofArbitraryRangeLimitAtEndOfInterval() {
        // Choose [0;H<<q]
        BigInteger H = BigInteger.valueOf(128 - 1);
        BigInteger m = BigInteger.valueOf(128 - 1);
        BigInteger gamma = UTIL.getRandomElement(BigInteger.ZERO, q, random);
        BigInteger V = PedersenCommitment.commit(g, m, h, gamma, p);

        int n = Bulletproof.getN(H);
        List<BigInteger> g_vector = group.newGenerators(n, random);
        List<BigInteger> h_vector = group.newGenerators(n, random);

        BulletproofExtensionStatement stmnt = new BulletproofExtensionStatement(
                H,
                new BulletproofStatement.Builder()
                        .setN(Bulletproof.getN(H))
                        .setV(V) // g^v h^t
                        .setPK(pk)
                        .set_G_Vector(g_vector)
                        .set_H_Vector(h_vector)
                        .setUVector(fakeUVector)
                        .build()
        );
        BulletproofSecret secret = new BulletproofSecret(m, gamma);
        Pair<BulletproofProof, BulletproofProof> proofPair = bulletproof.proveStatementArbitraryRange(stmnt, secret);

        boolean verification = bulletproof.verifyStatementArbitraryRange(stmnt, proofPair);

        assertThat("Should be 1", verification, is(true));
    }


}
