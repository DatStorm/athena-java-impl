package project.sigma.sigma2;

import com.google.common.primitives.Bytes;
import project.CONSTANTS;
import project.UTIL;
import project.dao.sigma2.ELProof;
import project.dao.sigma2.ELStatement;
import project.dao.sigma2.ElSecret;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class Sigma2EL {
    private final MessageDigest hashH;
    private final Random random;

    private static final int t = CONSTANTS.SIGMA2_EL_SECURITY_PARAM_T;
    private static final int l = CONSTANTS.SIGMA2_EL_SECURITY_PARAM_L;
    private static final int s1 = CONSTANTS.SIGMA2_EL_SECURITY_PARAM_S1;
    private static final int s2 = CONSTANTS.SIGMA2_EL_SECURITY_PARAM_S2;

    // https://www.quora.com/How-many-digits-are-in-a-512-bit-number
    //FIXME: article says |b|=512bits
    private static final BigInteger b = new BigInteger("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084095");

    public Sigma2EL(MessageDigest hash, Random random) {
        this.hashH = hash;
        this.random = random;
    }


    public ELProof prove(ELStatement statement, ElSecret secret) {
        BigInteger x = secret.x;

        if (!UTIL.BIGINT_IN_RANGE(BigInteger.ZERO, b, x)) {
            System.err.printf("Secret x=%d not in range [%d,%d] \n", x, BigInteger.ZERO, b);
        }
        BigInteger r1 = secret.r1;
        BigInteger r2 = secret.r2;
        //---------------
        BigInteger g1 = statement.g1;
        BigInteger g2 = statement.g2;
        BigInteger h1 = statement.h1;
        BigInteger h2 = statement.h2;
        BigInteger p = statement.group.p;
        BigInteger q = statement.group.q;

        /* ********
         * Step 1: get random range variables.
         *********/
        BigInteger w = getElementFromInterval(l, t, 0, b, random);
        BigInteger n1 = getElementFromInterval(l, t, s1, p, random);
        BigInteger n2 = getElementFromInterval(l, t, s2, p, random);

        // W1 = g1^w * h1^n1
        // W2 = g2^w * h2^n2
        BigInteger W1 = g1.modPow(w, p).multiply(h1.modPow(n1, p)).mod(p);
        BigInteger W2 = g2.modPow(w, p).multiply(h2.modPow(n2, p)).mod(p);

        /* *******************
         * Step 2: Create c = H(W1 || W2)
         *********************/
        BigInteger c = hash(W1, W2);


        /* *******************
         * Step 3: Create D,D1,D2
         *********************/
        BigInteger D = w.add(c.multiply(x).mod(q)); // FIXME: Should be in Zq.
        BigInteger D1 = n1.add(c.multiply(r1).mod(q)); // FIXME: Should be in Zq.
        BigInteger D2 = n2.add(c.multiply(r2).mod(q)); // FIXME: Should be in Zq.


        return new ELProof(c, D, D1, D2);
    }


    public boolean verify(ELStatement statement, ELProof proof) {
        BigInteger p = statement.group.p;
        BigInteger c = proof.c;


        /*
         * Compute X1
         */
        BigInteger y1 = statement.y1;
        BigInteger g1 = statement.g1;
        BigInteger h1 = statement.h1;
        BigInteger D = proof.D;
        BigInteger D1 = proof.D1;
        BigInteger X1 = createX(p, c, y1, g1, h1, D, D1);


        /*
         * Compute X2
         */
        BigInteger y2 = statement.y2;
        BigInteger g2 = statement.g2;
        BigInteger h2 = statement.h2;
        BigInteger D2 = proof.D2;
        BigInteger X2 = createX(p, c, y2, g2, h2, D, D2);


        /*
         * Compute new c.
         */
        BigInteger c_hashed = hash(X1, X2);

        return c.compareTo(c_hashed) == 0;
    }

    private BigInteger createX(BigInteger p, BigInteger c, BigInteger y, BigInteger g, BigInteger h, BigInteger D, BigInteger d1_OR_d2) {
        BigInteger g_D = g.modPow(D,p);
        BigInteger h_D1_OR_D2 = h.modPow(d1_OR_d2,p);
        BigInteger y_negC = y.modPow(c.negate(),p); // c.negate() => (-c)
        BigInteger g_D_mult_h_D1_OR_D2 = g_D.multiply(h_D1_OR_D2).mod(p);
        // = X
        return g_D_mult_h_D1_OR_D2.multiply(y_negC).mod(p);
    }

    public static BigInteger getElementFromInterval(int l, int t, int s, BigInteger p, Random random) {
        // n1 \in [1; 2^{l+t+s1} * p-1]
        int exponent = l + t + s;
        BigInteger endInclusive = BigInteger.TWO.pow(exponent).multiply(p);
        return UTIL.getRandomElement(endInclusive, random);
    }

    public static BigInteger pickRand_r1(Random random, BigInteger p) {
        return pickRand_r(random, s1, p);
    }

    public static BigInteger pickRand_r2(Random random, BigInteger p) {
        return pickRand_r(random, s2, p);
    }

    public static BigInteger pickRand_r(Random random, int s, BigInteger p) {
        // r2 \in [-2^{s2} * p+1; 2^{s2} * p-1]
        BigInteger startInclusive = BigInteger.TWO.pow(s).multiply(p).negate().add(BigInteger.ONE);
        BigInteger endExclusive = BigInteger.TWO.pow(s).multiply(p);
        BigInteger r = UTIL.getRandomElement(startInclusive, endExclusive, random);
        return r;
    }

    public BigInteger hash(BigInteger a, BigInteger b) {
        byte[] bytes_a = a.toByteArray();
        byte[] bytes_b = b.toByteArray();
        byte[] concatenated = Bytes.concat(bytes_a, bytes_b);
        byte[] hashed = this.hashH.digest(concatenated); // =>


        // TODO: hash output should be 2*t bits
        assert hashed.length == 2 * t / 8 : "Hash output should be 2t + hashed.length= " + hashed.length + ", t2=" + (2 * t / 8);
        return new BigInteger(1, hashed);
    }

}
