package cs.au.athena.bulletproof;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
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
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;


@Tag("TestBulletProofInvalid")
@DisplayName("Test BulletProof Invalid")
public class TestBulletProofInvalid {
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
    void TestSigma2BulletProofOutOfRange() {
        // m \not in [0, 2^5 -1] = [0, 31]
        BigInteger m = BigInteger.valueOf(32);
        int n = 5;

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
        assertFalse("Should return 0", verification);
    }
    
    
    @Test()
    void TestSigma2BulletProofArbitraryRangeOutsideInterval() {
        // Choose [0;H<<q]
        BigInteger H = BigInteger.valueOf(102);
        BigInteger m = BigInteger.valueOf(103);
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

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            Pair<BulletproofProof, BulletproofProof> proofPair = bulletproof.proveStatementArbitraryRange(stmnt, secret);
            boolean verification = bulletproof.verifyStatementArbitraryRange(stmnt, proofPair);
        });

        assertEquals("m is outside the range", exception.getMessage());

    }
}
