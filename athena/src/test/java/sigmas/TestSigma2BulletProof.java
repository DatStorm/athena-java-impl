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

import static org.junit.Assert.*;
import static project.UTIL.getRandomElement;

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
    void TestSigma2BulletProofInnerPrd_l_r() {
        BigInteger m = BigInteger.valueOf(5);
        int n = 10;
        BigInteger q = BigInteger.valueOf(155L);

        /*
         * Challenge 1
         */
        BigInteger z = BigInteger.valueOf(136L);
        BigInteger y = BigInteger.valueOf(47L);

        /*
         * Response 1
         */
        BigInteger t1 =  BigInteger.valueOf(128L);
        BigInteger t2 =  BigInteger.valueOf(82L);

        /*
         * Challenge 2 V -> P [x]
         */
        BigInteger x = BigInteger.valueOf(47L);


        /*
         * Response 2: P -> V [tau_x, mu, t_hat, l, r]
         */
        // [1, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        List<BigInteger> a_L = sigma2.extractBits(m, n);
        List<BigInteger> list_1n = sigma2.generateList(BigInteger.ONE, n, q);

        // [0, 154, 0, 154, 154, 154, 154, 154, 154, 154]
        List<BigInteger> a_R = UTIL.subtractLists(a_L, list_1n, q);

        
        List<BigInteger> yn_vector = sigma2.generateList(y, n, q);
        System.out.println("Y: " + y);
        System.out.println("Yn: " + yn_vector);


        List<BigInteger> s_L = UTIL.getRandomElements(q, n, random);
        List<BigInteger> l_vector = sigma2.compute_l_vector(n,q,a_L,s_L,z,x);

        List<BigInteger> s_R = UTIL.getRandomElements(q, n, random);
        List<BigInteger> r_vector = sigma2.compute_r_vector(n,q,a_R,s_R,z,x,yn_vector);
        BigInteger t_hat = UTIL.dotProduct(l_vector,r_vector,q);


        BigInteger m_z2 = m.multiply(z.pow(2)).mod(q);

        BigInteger t1x = t1.multiply(x).mod(q);
        BigInteger t2x2 = t2.multiply(x.pow(2)).mod(q);
        BigInteger t0 = m_z2.add(sigma2.delta(y, z, n, q)).mod(q);
        BigInteger t_polynomial = t0.add(t1x).mod(q).add(t2x2).mod(q);

        assertEquals("Should be the same", t_hat,t_polynomial);

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
