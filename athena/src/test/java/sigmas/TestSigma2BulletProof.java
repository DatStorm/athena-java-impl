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

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertTrue;

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
        sigma2 = new Bulletproof(factory.getHash());

    }


    @Test
    void TestSigma2BulletProof() {
        BigInteger m = BigInteger.valueOf(5);
        int n = 10;

        // \gamma \in Z_q =[0,q-1]
        BigInteger gamma = UTIL.getRandomElement(q, random);
        BigInteger V = g.modPow(m, p).multiply(h.modPow(gamma, p)).mod(p);
        BulletproofStatement stmnt = new BulletproofStatement(n, V, pk);

        BulletproofSecret secret = new BulletproofSecret(m, gamma);
        BulletproofProof proof = sigma2.proveStatement(stmnt, secret);

        boolean verification = sigma2.verifyStatement(stmnt, proof);

        assertTrue("Should return 1", verification);


    }
}
