package project.sigma.sigma2;

import com.google.common.primitives.Bytes;
import project.CONSTANTS;
import project.UTIL;
import project.dao.sigma2.*;
import project.elgamal.Group;
import project.factory.Factory;

import java.math.BigInteger;
import java.security.DigestException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

public class Sigma2 {
    private final Sigma2EL sigma2EL;
    private final Sigma2SQR sigma2SQR;
    private final MessageDigest hashH;

    /**
     * Security params.
     * We employ two large security parameters k1
     * and k2. k1 is much smaller than k2. However, k1 is large
     * enough such that 1/(k1 − 1) is a negligible probability. A
     * recommendation for their values is that k1 is large but much
     * smaller than the order of G (e.g. 160 bits long) and k2 is
     * larger than the order of G (e.g. longer than 1024 bits).
     */
    private final static BigInteger k1 = BigInteger.valueOf(CONSTANTS.SIGMA2_SECURITY_PARAM_k1);
    private final static BigInteger k2 = BigInteger.valueOf(CONSTANTS.SIGMA2_SECURITY_PARAM_k2);
    private final Random random;


    public Sigma2(MessageDigest hashH,Random random) {
        this.hashH = hashH;
        this.random = random;
        this.sigma2EL = new Sigma2EL(this.hashH, random);
        this.sigma2SQR = new Sigma2SQR(this.sigma2EL, random);
    }

    public Sigma2Proof proveCiph(Sigma2Statement statement, Sigma2Secret secret) {
        // Get the secret parts of the relation
        BigInteger m = secret.m; // 5
        BigInteger r = secret.r; // 2763

        // Get the publicly known parts
        BigInteger c = statement.c;

        BigInteger h = statement.pk.getH();
        BigInteger g = statement.pk.getGroup().g;
        BigInteger p = statement.pk.getGroup().p;
        BigInteger q = statement.pk.getGroup().q;
        Group group = statement.pk.getGroup();

        BigInteger a = statement.a;
        BigInteger b = statement.b;


        /* ********
         * Step 1: Create (c1,c2)
         *********/
        List<BigInteger> c1_c2 = createC1_C2(a, b, c, g, p);
        BigInteger c1 = c1_c2.get(0);
        BigInteger c2 = c1_c2.get(1);


        /* ********
         * Step 2: Run EL_0
         *********/

        //Choose randomly in Z_k2
        BigInteger r_prime = sampleRandomElementInZ_k2(this.random);

        // = b - m + 1
        BigInteger b_m_add_1 = b.subtract(m).add(BigInteger.ONE);
        // c^\prime = c1^{b - m + 1} * h^{r_prime}
        BigInteger c_prime = createC_prime(c1, h, r_prime, b_m_add_1, p);


        // x = b - m + 1
        // r1 = - r
        // r2 = r^\prime
        ElSecret secretEL_0 = new ElSecret(b_m_add_1, r.negate(), r_prime); // x, r1, r2


        // y1 => c2,
        // y2 => c^\prime,
        // g1 => g,
        // g2 => c1,
        // h1 => h,
        // h2 => h
        ELStatement stmntEL_0 = new ELStatement(c2, c_prime, g, c1, h, h, group); // y1, y2, g1, g2, h1, h2, group
        ELProof proofEL_0 = sigma2EL.prove(stmntEL_0, secretEL_0);



        /* ********
         * Step 3: SQR1(w, r'' | c', h | c'')
         *********/
        BigInteger w = UTIL.getRandomElement(BigInteger.ONE, k2, random);               // Z_k2 \ {0}
        BigInteger r_prime_prime = UTIL.getRandomElement(BigInteger.ZERO, k2, random);  // Z_k2
        BigInteger w_squared = w.pow(2);
        BigInteger h_r_prime_prime = h.modPow(r_prime_prime, p);
        BigInteger c_prime_prime = c_prime.modPow(w_squared, p).multiply(h_r_prime_prime).mod(p);

        // SQR1(w, r'' | c', h | c'')
        SQRSecret secretSQR_1 = new SQRSecret(w, r_prime_prime); // x => w, r => r^{\prime \prime}
        SQRStatement statementSQR_1 = new SQRStatement(c_prime, h, c_prime_prime, group); //g => c^\prime, h => h, y1 => c^\prime\prime,
        SQRProof proofSQR_1 = sigma2SQR.prove(statementSQR_1, secretSQR_1);


        /* ********
         * Step 4: SQR2(m_4, r_3 | g, h | c'_3)
         *********/

        // Randomly choose m1, m2 and m4
        // = m - a + 1
        BigInteger m_a_add1 = m.subtract(a).add(BigInteger.ONE);

        // pick from {0,..., w^2 * (m − a + 1) * (b − m + 1) }
        BigInteger w2_m_a_add1_b_m_add1 = w_squared.multiply(m_a_add1).multiply(b_m_add_1);

        assert w2_m_a_add1_b_m_add1.compareTo(BigInteger.ZERO) > 0 : "Should be > 0";

        // returns = m1,m2,m3,m4
        List<BigInteger> mList = sampleMs(w2_m_a_add1_b_m_add1, q);
        BigInteger m1 = mList.get(0);
        BigInteger m2 = mList.get(1);
        BigInteger m3 = mList.get(2);
        BigInteger m4 = mList.get(3);


        // Randomly choose r1, r2, r3 to satisfy r1+r2+r3 = w^2((b − m + 1)r + r') + r''
        // = (b − m + 1)r
        BigInteger b_m_add_1_mult_r = b_m_add_1.multiply(r);
        // = (b − m + 1)r + r'
        BigInteger b_m_add_1_mult_r_r_prime = b_m_add_1_mult_r.add(r_prime);
        // = w^2((b − m + 1)r + r')
        BigInteger w2_b_m_add_1_mult_r_r_prime = w_squared.multiply(b_m_add_1_mult_r_r_prime);
        // = w^2((b − m + 1)r + r') + r''
        BigInteger w2_b_m_add_1_mult_r_r_prime_r_prime_prime = w2_b_m_add_1_mult_r_r_prime.add(r_prime_prime);

        // returns = r1,r2,r3
        List<BigInteger> rList = sampleRs(w2_b_m_add_1_mult_r_r_prime_r_prime_prime);
        BigInteger r1 = rList.get(0);
        BigInteger r2 = rList.get(1);
        BigInteger r3 = rList.get(2);

        // Compute c'_1, c'_2, c'_3
        BigInteger c_prime_1 = g.modPow(m1, p).multiply(h.modPow(r1, p)).mod(p); ///FIXME: mod q in the exponent???
        BigInteger c_prime_2 = g.modPow(m2, p).multiply(h.modPow(r2, p)).mod(p); //FIXME: mod q in the exponent???
        // c3' = (c'' / c1') * c2' OR c'' / (c1' * c2') = c'' * c1'^{-1} * c2'^{-1}
        BigInteger c_prime_3 = c_prime_prime.multiply(c_prime_1.modInverse(p)).multiply(c_prime_2.modInverse(p)).mod(p);

        // SQR2(m_4, r_3 | g, h | c'_3)
        SQRStatement statementSQR_2 = new SQRStatement(g, h, c_prime_3, group);
        SQRSecret secretSQR_2 = new SQRSecret(m4, r3);
        SQRProof proofSQR_2 = sigma2SQR.prove(statementSQR_2, secretSQR_2);


        /* ********
         * Step 5: Make non-interactive using Fiat-Shamir
         *********/
//        BigInteger _s = UTIL.getRandomElement(BigInteger.ONE, k1, random);               // Z_k1 \ {0}
//        BigInteger _t = UTIL.getRandomElement(BigInteger.ONE, k1, random);               // Z_k1 \ {0}
//        System.out.println("_s=" + _s);
//        System.out.println("_t=" + _t);

        List<BigInteger> s_t = hash(c1, c2,                                 // (c1,c2)
                c_prime,                                                    // c'
                proofEL_0.c, proofEL_0.D, proofEL_0.D1, proofEL_0.D2,       // c^(0), D^(0), D1^(0), D2^(0)
                c_prime_prime,                                              // c''
                proofSQR_1.c, proofSQR_1.D, proofSQR_1.D1, proofSQR_1.D2,   // c^(1), D^(1), D1^(1), D2^(1)
                c_prime_1, c_prime_2, c_prime_3,                            // c'_1, c'_2, c'_3
                proofSQR_2.c, proofSQR_2.D, proofSQR_2.D1, proofSQR_2.D2);  // c^(2), D^(2), D1^(2), D2^(2)

        BigInteger s = s_t.get(0);
        BigInteger t = s_t.get(1);

        /* ********
         * Step 6:
         *********/
        BigInteger x = s.multiply(m1).add(m2).add(m3);
        BigInteger y = m1.add(t.multiply(m2)).add(m3);
        BigInteger u = s.multiply(r1).add(r2).add(r3);
        BigInteger v = r1.add(t.multiply(r2)).add(r3);


        return new Sigma2Proof(
                stmntEL_0,
                statementSQR_1,
                statementSQR_2,
                proofEL_0,
                proofSQR_1,
                proofSQR_2,
                c1, c2,
                c_prime_prime,
                c_prime_1, c_prime_2, c_prime_3,
                s, t,
                x, y, u, v);
    }

    private List<BigInteger> hash(BigInteger... values) {
        byte[] concatenated = new byte[]{};
        for (BigInteger integer : values) {
            concatenated = Bytes.concat(concatenated, integer.toByteArray());
        }

        byte[] hashed = this.hashH.digest(concatenated);

        // find the middle element
        int middle = hashed.length / 2;
        byte[] s_byte = new byte[middle];
        byte[] t_byte = new byte[middle];
        for (int i = 0; i < middle; i++) {

            // fill s_bytes with the first H(..)/2 bytes
            s_byte[i] = hashed[i];

            // fill s_bytes with the last H(..)/2 bytes
            t_byte[i] = hashed[i + middle];
        }

        // create two big ints and convert to longs.
        long l_s = new BigInteger(1, s_byte).longValue();
        long l_t = new BigInteger(1, t_byte).longValue();

        BigInteger s = UTIL.getRandomElement(BigInteger.ONE, k1, new Random(l_s)); // use as seed
        BigInteger t = UTIL.getRandomElement(BigInteger.ONE, k1, new Random(l_t)); // use as seed

        // Validate that the are in the right range.
        boolean s_should_be_in_Zk1_removed_0 = UTIL.BIGINT_IN_RANGE(BigInteger.ONE, k1, s);
        boolean t_should_be_in_Zk1_removed_0 = UTIL.BIGINT_IN_RANGE(BigInteger.ONE, k1, t);

        if (!s_should_be_in_Zk1_removed_0) {
            System.out.println("Sigma2.hash:: s output of hash not in Z_k1 - {0}");
            System.out.println("Sigma2.hash:: s=" + s );
            System.out.println("Sigma2.hash:: k1=" + k1 );
        }
        if (!t_should_be_in_Zk1_removed_0) {
            System.out.println("Sigma2.hash:: t output of hash not in Z_k1 - {0}");
            System.out.println("Sigma2.hash:: t=" + t );
            System.out.println("Sigma2.hash:: k1=" + k1 );
        }

        return Arrays.asList(s, t);
    }

    public static List<BigInteger> createC1_C2(BigInteger a, BigInteger b, BigInteger c, BigInteger g, BigInteger p) {
        // c1 = c / g^{a-1} mod p

        BigInteger c1 = c.multiply(g.modPow(a.subtract(BigInteger.ONE), p).modInverse(p)).mod(p);
        // c2 = g^{b+1}/c mod p
        BigInteger c2 = g.modPow(b.add(BigInteger.ONE), p).multiply(c.modInverse(p)).mod(p);

        return Arrays.asList(c1, c2);
    }

    public static BigInteger createC_prime(BigInteger c1, BigInteger h, BigInteger r_prime, BigInteger b_m_add_1, BigInteger p) {
        // = h^{r^\prime}
        BigInteger h_r_prime = h.modPow(r_prime, p);
        // c^\prime = c1^{b - m + 1} * h^{r_prime}
        BigInteger c_prime = c1.modPow(b_m_add_1, p).multiply(h_r_prime).mod(p);
        return c_prime;
    }

    private List<BigInteger> sampleRs(BigInteger targetValue) {
        //Sample two values, and use them as delimiters for the r values.
        BigInteger delimiter1 = UTIL.getRandomElement(targetValue, this.random);
        BigInteger delimiter2 = UTIL.getRandomElement(targetValue, this.random);

        // Find the lowest delimiter
        BigInteger delimiterLow;
        BigInteger delimiterHigh;
        boolean delim1IsLowerThanDelim2 = delimiter1.compareTo(delimiter2) == -1;
        if (delim1IsLowerThanDelim2) {
            delimiterLow = delimiter1;
            delimiterHigh = delimiter2;
        } else {
            delimiterLow = delimiter2;
            delimiterHigh = delimiter1;
        }

        // Use delimiters to choose r values
        BigInteger r1 = delimiterLow;
        BigInteger r2 = delimiterHigh.subtract(delimiterLow);
        BigInteger r3 = targetValue.subtract(delimiterHigh);


        BigInteger sum = r1.add(r2).add(r3);
        if (!targetValue.equals(sum)) {
            throw new RuntimeException("R values not sampled correctly");
        }

        return Arrays.asList(r1, r2, r3);
    }

    //FIXME: Plz kill me now
    private List<BigInteger> sampleMs(BigInteger upperBoundExclusive, BigInteger q) {

        // Pick m4 randomly in [0;sqrt(bound)], ensuring that m3 is in [0;bound]
        //TODO: Should we pick m4 in [0;bound] and m3 as m4^2 mod p ?
        BigInteger m4 = UTIL.getRandomElement(upperBoundExclusive.sqrt(), this.random);
        BigInteger m3 = m4.pow(2);

        // Choose m1,m2. We select m1 randomly in the interval, and set m2 to the remaining.
        BigInteger m1 = UTIL.getRandomElement(upperBoundExclusive.subtract(m3), this.random);
        BigInteger m2 = upperBoundExclusive.subtract(m1).subtract(m3);

        BigInteger m1_m2_m3 = m1.add(m2).add(m3); //FIXME: shoul there be modulo q?


        assert m1.signum() >= 0 : "m1.signum() < 0";
        assert m2.signum() >= 0 : "m2.signum() < 0";
        assert m3.signum() >= 0 : "m3.signum() < 0";
        assert m4.signum() >= 0 : "m4.signum() < 0";
        assert upperBoundExclusive.equals(m1_m2_m3);

        if (!upperBoundExclusive.equals(m1_m2_m3)) {
            throw new RuntimeException("M values not sampled correctly");
        }

        return Arrays.asList(m1, m2, m3, m4);
    }

    public static BigInteger sampleRandomElementInZ_k2(Random random) {
        return UTIL.getRandomElement(k2, random);
    }


    /* ********
     * Step 7:
     *********/
    public boolean verifyCipher(Sigma2Statement statement, Sigma2Proof proof) {
        // public knowledge
        BigInteger c = statement.c;
        BigInteger a = statement.a;
        BigInteger b = statement.b;
        BigInteger g = statement.pk.getGroup().getG();
        BigInteger h = statement.pk.getH();
        BigInteger p = statement.pk.getGroup().getP();
        BigInteger q = statement.pk.getGroup().getQ();

        //Verify EL_0
        boolean verificationEL0 = sigma2EL.verify(proof.statementEL_0, proof.proofEL_0);
        if (!verificationEL0) {
            System.out.println("sigma2EL_0 failed");
            return false;
        }

        //Verify SQR_1
        boolean verificationSQR1 = sigma2SQR.verify(proof.statementSQR_1, proof.proofSQR_1);
        if (!verificationSQR1) {
            System.out.println("sigma2SQR_1 failed");
            return false;
        }

        //Verify SQR_2
        boolean verificationSQR2 = sigma2SQR.verify(proof.statementSQR_2, proof.proofSQR_2);
        if (!verificationSQR2) {
            System.out.println("sigma2SQR_2 failed");
            return false;
        }

        // Verify the overall Sigma2 proof
        BigInteger c1 = proof.c1;
        BigInteger c2 = proof.c2;
        BigInteger c_prime_1 = proof.c_prime_1;
        BigInteger c_prime_2 = proof.c_prime_2;
        BigInteger c_prime_3 = proof.c_prime_3;
        BigInteger c_prime_prime = proof.c_prime_prime;
        BigInteger s = proof.s;
        BigInteger t = proof.t;
        BigInteger x = proof.x;
        BigInteger y = proof.y;
        BigInteger u = proof.u;
        BigInteger v = proof.v;

        // c1 = c * g^{-(a−1)} mod p
        int check1 = c1.compareTo(c.multiply(g.modPow(a.subtract(BigInteger.ONE), p).modInverse(p)).mod(p));
//        int check1 = c1.compareTo(c.multiply(g.modPow(a.subtract(BigInteger.ONE).negate(), p).mod(p)));
        if (check1 != 0) { // compareTo returns 0 if the 2 BigIntegers are equal
            System.out.println("c1 != c * g^{-(a−1)} mod p");
            return false;
        }

        // c2 = g^{b+1} * c^{-1} mod p
        int check2 = c2.compareTo(g.modPow(b.add(BigInteger.ONE), p).multiply(c.modInverse(p)).mod(p));
        if (check2 != 0) {// compareTo returns 0 if the 2 BigIntegers are equal
            System.out.println("c2 != g^{b+1} * c^{-1} mod p");
            return false;
        }

        // c'' = c'_1 * c'_2 * c'_3 mod p
        int check3 = c_prime_prime.compareTo(c_prime_1.multiply(c_prime_2).multiply(c_prime_3).mod(p));
        if (check3 != 0) { // compareTo returns 0 if the 2 BigIntegers are equal
            System.out.println("c'' != c'_1 * c'_2 * c'_3 mod p");
            return false;
        }

        // c'_1^s * c'_2 * c'_3 = g^x h^u mod p
        BigInteger check4Part1 = c_prime_1.modPow(s, p).multiply(c_prime_2).multiply(c_prime_3).mod(p);
        BigInteger check4Part2 = g.modPow(x, p).multiply(h.modPow(u, p)).mod(p);
        int check4 = check4Part1.compareTo(check4Part2);
        if (check4 != 0) { // compareTo returns 0 if the 2 BigIntegers are equal
            System.out.println("c'_1^s * c'_2 * c'_3 != g^x h^u mod p");
            return false;
        }

        // c'_1 * c'_2^t * c'_3 = g^y h^v mod p
        BigInteger check5Part1 = c_prime_1.multiply(c_prime_2.modPow(t, p)).multiply(c_prime_3).mod(p);
        BigInteger check5Part2 = g.modPow(y, p).multiply(h.modPow(v, p)).mod(p);
        int check5 = check5Part1.compareTo(check5Part2);
        if (check5 != 0) { // compareTo returns 0 if the 2 BigIntegers are equal
            System.out.println("c'_1 * c'_2^t * c'_3 != g^y h^v mod p");
            return false;
        }

        // x>0
        int check6 = x.compareTo(BigInteger.ZERO);
        if (check6 != 1) { // compareTo returns 1 if x>0
            System.out.println("x<=0");
            return false;
        }

        // y>0
        int check7 = y.compareTo(BigInteger.ZERO);
        if (check7 != 1) { // compareTo returns 1 if y>0
            System.out.println("V.y= " + y);
            return false;
        }

        return true;
    }


}
