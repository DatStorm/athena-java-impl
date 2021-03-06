package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.UTIL;
import project.dao.bulletproof.BulletproofProof;
import project.dao.bulletproof.BulletproofSecret;
import project.dao.bulletproof.BulletproofStatement;
import project.elgamal.ElGamalPK;
import project.factory.Factory;
import project.factory.MainFactory;
import project.sigma.bulletproof.Bulletproof;
import project.sigma.bulletproof.PedersenCommitment;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

@Tag("TestsSigma2BulletProof")
@DisplayName("Test Sigma2 BulletProof")
public class TestSigma2BulletProof {


    private ElGamalPK pk;
    private Bulletproof sigma2;
    private Random random;

    private BigInteger g;
    private BigInteger q;
    private BigInteger p;
    private BigInteger h;


    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        random = factory.getRandom();
        pk = factory.getPK();
        g = pk.getGroup().getG();
        p = pk.getGroup().getP();
        q = pk.getGroup().getQ();
        h = pk.getH();
        sigma2 = new Bulletproof(factory.getHash(), factory.getRandom());

    }


    @Test
    void TestSigma2PedersenCommit() {
        BigInteger order = BigInteger.valueOf(150);

        BigInteger _g = BigInteger.valueOf(2);
        BigInteger _m = BigInteger.valueOf(4); // 2^4 = 16

        BigInteger _h = BigInteger.valueOf(3);
        BigInteger _r = BigInteger.valueOf(2); // 3^2 = 9


        BigInteger com = PedersenCommitment.commit(_g,_m,_h,_r, order);

        assertTrue(com.equals(BigInteger.valueOf(144)));


        /*
         * Test mod in commit works.
         */
        BigInteger order2 = BigInteger.valueOf(100);
        BigInteger com2 = PedersenCommitment.commit(_g,_m,_h,_r, order2);

        assertFalse(com2.equals(BigInteger.valueOf(144)));
        assertTrue(com2.equals(BigInteger.valueOf(44)));

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
        BigInteger V = PedersenCommitment.commit(g,m,h,gamma, p);
        BulletproofStatement stmnt = new BulletproofStatement(n, V, pk);

        BulletproofSecret secret = new BulletproofSecret(m, gamma);
        BulletproofProof proof = sigma2.proveStatement(stmnt, secret);

        boolean verification = sigma2.verifyStatement(stmnt, proof);

        assertTrue("Should return 1", verification);

    }
}
