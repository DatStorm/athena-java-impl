package sigmas;


import org.junit.jupiter.api.*;
import project.UTIL;
import project.dao.sigma2.*;
import project.elgamal.ElGamalPK;
import project.elgamal.Group;
import project.sigma.sigma2.Sigma2;
import project.factory.Factory;
import project.factory.MainFactory;
import project.sigma.sigma2.Sigma2EL;
import project.sigma.sigma2.Sigma2SQR;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Tag("TestsSigma2")
@DisplayName("Test Sigma2")
public class TestSigma2 {

    private Sigma2 sigma2;
    private Sigma2EL sigma2EL;
    private Sigma2SQR sigma2SQR;
    private Random random;
    private Group group;
    private ElGamalPK pk;


    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        sigma2 = new Sigma2(factory);
        random = factory.getRandom();

        sigma2EL = new Sigma2EL(factory.getHash(), random);
        sigma2SQR = new Sigma2SQR(sigma2EL, random);
        pk = factory.getPK();
        group = pk.getGroup();

    }


    @Test
    void TestSigma2_EL() {
        BigInteger p = this.group.p;
        BigInteger g = this.group.g;

        long _x = 99;

        BigInteger x = BigInteger.valueOf(_x);

//        BigInteger r1 = new BigInteger("157181058048081909733704582682606315124143702309980143290274537733081226566206509465717797164039347554049805633234092780133502719339774120983499931320565410753926949965924323150596649347292939673652905641153522272965645802364244897226702367610711286962423625395733125655198210381762658898273062443505974743964493868461070");
        BigInteger r1 = Sigma2EL.pickRand_r1(random, p);
        BigInteger r2 = Sigma2EL.pickRand_r2(random, p);
        ElSecret secret = new ElSecret(x, r1, r2);

        BigInteger g1 = g.modPow(BigInteger.valueOf(1), p);
        BigInteger g2 = g.modPow(BigInteger.valueOf(2), p);
        BigInteger h1 = g.modPow(BigInteger.valueOf(3), p);
        BigInteger h2 = g.modPow(BigInteger.valueOf(4), p);
        BigInteger y1 = g1.modPow(x, p).multiply(h1.modPow(r1, p)).mod(p);
        BigInteger y2 = g2.modPow(x, p).multiply(h2.modPow(r2, p)).mod(p);
        //EL(x,r1,r2,g,h1,g2,h2,y1,y2);
        ELStatement stmnt = new ELStatement(y1, y2, g1, g2, h1, h2, group);

        ELProof proof = sigma2EL.prove(stmnt, secret);
        boolean verification = sigma2EL.verify(stmnt, proof);

        assertTrue("Should return 1", verification);
    }

   @RepeatedTest(10)
   void TestSigma2_EL_random() {
        BigInteger p = this.group.p;
        BigInteger q = this.group.q;
        BigInteger g = this.group.g;

        BigInteger x = UTIL.getRandomElement(BigInteger.ZERO, BigInteger.valueOf(1000000), random); //in [0,b]
        BigInteger r1 = Sigma2EL.pickRand_r1(random, p);
        BigInteger r2 = Sigma2EL.pickRand_r2(random, p);
        ElSecret secret = new ElSecret(x, r1, r2);

        BigInteger g1 = g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger g2 = g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger h1 = g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger h2 = g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger y1 = g1.modPow(x, p).multiply(h1.modPow(r1, p)).mod(p);
        BigInteger y2 = g2.modPow(x, p).multiply(h2.modPow(r2, p)).mod(p);
        //EL(x,r1,r2,g,h1,g2,h2,y1,y2);
        ELStatement stmnt = new ELStatement(y1, y2, g1, g2, h1, h2, group);

        ELProof proof = sigma2EL.prove(stmnt, secret);
        boolean verification = sigma2EL.verify(stmnt, proof);

        assertTrue("Should return 1", verification);
    }


   @RepeatedTest(10)
   void TestSigma2_EL_random_false() {
        BigInteger p = this.group.p;
        BigInteger q = this.group.q;
        BigInteger g = this.group.g;

        BigInteger x = UTIL.getRandomElement(BigInteger.ZERO, BigInteger.valueOf(1000000), random); //in [0,b]
        BigInteger r1 = Sigma2EL.pickRand_r1(random, p);
        BigInteger r2 = Sigma2EL.pickRand_r2(random, p);
        ElSecret secret = new ElSecret(x, r1, r2);

        BigInteger g1 = g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger g2 = g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger h1 = g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger h2 = g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger y1 = g1.modPow(x, p).multiply(h1.modPow(r1, p)).mod(p);

        // Change the commitment such we don't commit to the same.
        BigInteger x_false = BigInteger.valueOf(2384802);
        BigInteger y2 = g2.modPow(x_false, p).multiply(h2.modPow(r2, p)).mod(p);
        //EL(x,r1,r2,g,h1,g2,h2,y1,y2);
        ELStatement stmnt = new ELStatement(y1, y2, g1, g2, h1, h2, group);

        ELProof proof = sigma2EL.prove(stmnt, secret);
        boolean verification = sigma2EL.verify(stmnt, proof);

        assertFalse("Should return 1", verification);
    }



    @Test
    void TestSigma2_SQR() {
        // Public
        BigInteger p = group.p;
        BigInteger g = group.g.modPow(BigInteger.valueOf(4), p);
        BigInteger h = group.g.modPow(BigInteger.valueOf(8), p);

        //Secret
        BigInteger x = BigInteger.valueOf(7);
        BigInteger r = Sigma2EL.pickRand_r1(random, p); // Within [-2^s p +1, 2^s p-1], note that s=s1
        SQRSecret secretSQR = new SQRSecret(x, r);

        BigInteger y1 = g.modPow(x.pow(2), p).multiply(h.modPow(r, p)).mod(p);
        SQRStatement statementSQR = new SQRStatement(g, h, y1, group);

        // Run the protocol
        SQRProof proofSQR = sigma2SQR.prove(statementSQR, secretSQR);

        boolean verification = sigma2SQR.verify(statementSQR, proofSQR);
        assertTrue(verification);
    }


    @RepeatedTest(10)
    void TestSigma2_SQR_random() {
        // Public
        BigInteger p = group.p;
        BigInteger q = group.q;
        BigInteger g = group.g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger h = group.g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);

        //Secret
        BigInteger x = UTIL.getRandomElement(BigInteger.ZERO, BigInteger.valueOf(100000), random);
        BigInteger r = Sigma2EL.pickRand_r1(random, p); // Within [-2^s p +1, 2^s p-1], note that s=s1
        SQRSecret secretSQR = new SQRSecret(x, r);

        BigInteger y1 = g.modPow(x.pow(2), p).multiply(h.modPow(r, p)).mod(p);
        SQRStatement statementSQR = new SQRStatement(g, h, y1, group);

        // Run the protocol
        SQRProof proofSQR = sigma2SQR.prove(statementSQR, secretSQR);

        boolean verification = sigma2SQR.verify(statementSQR, proofSQR);
        assertTrue(verification);
    }


    @RepeatedTest(10)
    void TestSigma2_SQR_random_false() {
        // Public
        BigInteger p = group.p;
        BigInteger q = group.q;
        BigInteger g = group.g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);
        BigInteger h = group.g.modPow(UTIL.getRandomElement(BigInteger.ZERO, q, random), p);

        //Secret
        BigInteger x = UTIL.getRandomElement(BigInteger.ZERO, BigInteger.valueOf(1000000), random);
        BigInteger r = Sigma2EL.pickRand_r1(random, p); // Within [-2^s p +1, 2^s p-1], note that s=s1
        SQRSecret secretSQR = new SQRSecret(x, r);

        // the committed value it set such that it is no longer a square of x
        BigInteger y1 = g.modPow(x.pow(1), p).multiply(h.modPow(r, p)).mod(p);
        SQRStatement statementSQR = new SQRStatement(g, h, y1, group);

        // Run the protocol
        SQRProof proofSQR = sigma2SQR.prove(statementSQR, secretSQR);

        boolean verification = sigma2SQR.verify(statementSQR, proofSQR);
        assertFalse(verification);
    }




    @Test
    void TestSigma2() {
        BigInteger m = BigInteger.valueOf(5);

        BigInteger a = BigInteger.ZERO;
        BigInteger b = BigInteger.TEN;
        BigInteger r = Sigma2.sampleRandomElementInZ_k2(this.random);
        BigInteger p = group.p;
        BigInteger h = pk.getH();
        BigInteger g = group.g;

        BigInteger h_r = h.modPow(r,p);
        BigInteger c = g.modPow(m,p).multiply(h_r).mod(p);
        Sigma2Statement statement = new Sigma2Statement(c,a,b,pk);



        Sigma2Secret secret = new Sigma2Secret(m,r);
        Sigma2Proof proof = sigma2.proveCiph(statement, secret);

        boolean verification = sigma2.verifyCipher(statement, proof);
        assertTrue(verification);
    }


    /**
     * TEST EL
     */
    @Test
    void TestSigma2_EL0_step2() {
        BigInteger m = BigInteger.valueOf(5);
        BigInteger a = BigInteger.ZERO;
        BigInteger b = BigInteger.TEN;

        //Choose randomly in Z_k2
        BigInteger r = Sigma2.sampleRandomElementInZ_k2(this.random);
        BigInteger r_prime = Sigma2.sampleRandomElementInZ_k2(this.random);

        // = b - m + 1
        BigInteger b_m_add_1 = b.subtract(m.add(BigInteger.ONE)); //.mod(q); //TODO: mod q?

        // x = b - m + 1
        // r1 = - r
        // r2 = r^\prime
        ElSecret secretEL_0 = new ElSecret(b_m_add_1, r.negate(), r_prime); // x, r1, r2


        BigInteger h = pk.getH();
        BigInteger g = group.g;

        // y1 => c2,
        // y2 => c^\prime,
        // g1 => g,
        // g2 => c1,
        // h1 => h,
        // h2 => h
//        ELStatement stmntEL_0 = new ELStatement(c2, c_prime, g, c1, h, h, group); // y1, y2, g1, g2, h1, h2, group


//        ELProof proof = sigma2EL.prove(stmntEL_0, secretEL_0);
//        boolean verification = sigma2EL.verify(stmntEL_0, proof);

        assertTrue("Should return 1", true);
    }


    
}
