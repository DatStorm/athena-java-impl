package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.dao.sigma2.ELProof;
import project.dao.sigma2.ELStatement;
import project.dao.sigma2.ElSecret;
import project.elgamal.Group;
import project.sigma.sigma2.Sigma2;
import project.factory.Factory;
import project.factory.MainFactory;
import project.sigma.sigma2.Sigma2EL;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertTrue;

@Tag("TestsSigma2")
@DisplayName("Test Sigma2")
public class TestSigma2 {

    private Sigma2 sigma2;
    private Sigma2EL sigma2EL;
    private Random random;
    private Group group;


    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        sigma2 = new Sigma2(factory);
        random = factory.getRandom();

        sigma2EL = new Sigma2EL(factory.getHash(), random);
        group = factory.getPK().getGroup();

    }


    @Test
    void TestSigma2_EL() {
        BigInteger p = this.group.p;
        BigInteger g = this.group.g;

        long _x = 111;

        System.out.println("1.");
        BigInteger x = BigInteger.valueOf(_x);
        BigInteger r1 = Sigma2EL.pickRand_r1(random, p);
        System.out.println("2.");
        BigInteger r2 = Sigma2EL.pickRand_r2(random, p);
        System.out.println("3.");
        ElSecret secret = new ElSecret(x, r1, r2);


        BigInteger g1 = g.modPow(BigInteger.valueOf(1), p);
        BigInteger g2 = g.modPow(BigInteger.valueOf(2), p);
        BigInteger h1 = g.modPow(BigInteger.valueOf(3), p);
        BigInteger h2 = g.modPow(BigInteger.valueOf(4), p);
        BigInteger y1 = g1.modPow(x, p).multiply(h1.modPow(r1, p)).mod(p);
        BigInteger y2 = g2.modPow(x, p).multiply(h2.modPow(r2, p)).mod(p);
        //EL(x,r1,r2,g,h1,g2,h2,y1,y2);
        ELStatement stmnt = new ELStatement(y1, y2, g1, g2, h1, h2, group);

        System.out.println("--> prove");
        ELProof proof = sigma2EL.prove(stmnt, secret);
        System.out.println("prove done");
        boolean verification = sigma2EL.verify(stmnt, proof);

        assertTrue("Should return 1", verification);
    }


    @Test
    void TestSigma2_SQR() {
        //make me!!!

//        boolean verification = sigma2SQR.verify()
//        assertTrue(verification)
    }
}
