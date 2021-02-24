package project.sigma.sigma2;

import project.UTIL;
import project.dao.sigma2.*;
import project.elgamal.Group;
import project.factory.Factory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

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
    private final static BigInteger k1 = BigInteger.valueOf(320); // k1 << k2   // TODO: CHANGE
    private final static BigInteger k2 = BigInteger.valueOf(1500); // 3000    // TODO: CHANGE
    private final Random random;


    public Sigma2(Factory factory) {
        this.hashH = factory.getHash();
        this.random = factory.getRandom();
        this.sigma2EL = new Sigma2EL(this.hashH, random);
        this.sigma2SQR = new Sigma2SQR(this.sigma2EL, random);
    }

    public Sigma2Proof proveCiph(Sigma2Statement statement, Sigma2Secret secret) {
        // Get the secret parts of the relation
        BigInteger m = secret.m;
        BigInteger r = secret.r;

        // Get the publicly known parts
        BigInteger c = statement.c;

        BigInteger h = statement.pk.getH();
        BigInteger g = statement.pk.getGroup().g;
        BigInteger p = statement.pk.getGroup().p;
        Group group = statement.pk.getGroup();

        BigInteger a = statement.a;
        BigInteger b = statement.b;


        /* ********
         * Step 1: Create (c1,c2)
         *********/
        // c1 = c / g^{a-1} mod p
        BigInteger c1 = c.multiply(g.modPow(a.subtract(BigInteger.ONE), p).modInverse(p).mod(p));
        // c2 = g^{b+1}/c mod p
        BigInteger c2 = g.modPow(b.add(BigInteger.ONE), p).multiply(c.modInverse(p)).mod(p);


        /* ********
         * Step 2: Run EL_0
         *********/

        //Choose randomly in Z_k2
        BigInteger r_prime = sampleRandomElementInZ_k2(this.random);

        // = b - m + 1
        BigInteger b_m_add_1 = b.subtract(m.add(BigInteger.ONE));
        // = h^{r^\prime}
        BigInteger h_r_prime = h.modPow(r_prime, p);
        // c^\prime = c1^{b - m + 1} * h^{r_prime}
        BigInteger c_prime = c1.modPow(b_m_add_1, p).multiply(h_r_prime).mod(p);


        // x = b - m + 1
        // r1 = - r
        // r2 = r^\prime
        ElSecret secretEL_0 = new ElSecret(b_m_add_1, r.negate(), r_prime); // x, r1, r2
//        ElSecret secretEL_0Test = ElSecret.newBuilder()
//            .setX(b_m_add_1)
//            .setR1(r.negate())
//            .setR2(r_prime)
//            .build();

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
        BigInteger m_a_add1 = m.subtract(a.add(BigInteger.ONE));
        BigInteger w2_m_a_add1_b_m_add1 = w_squared.multiply(m_a_add1).multiply(b_m_add_1);

        // returns = m1,m2,m3,m4
        List<BigInteger> mList = sampleMs(w2_m_a_add1_b_m_add1);
        BigInteger m1 = mList.get(0);
        BigInteger m2 = mList.get(1);
        BigInteger m3 = mList.get(2);
        BigInteger m4 = mList.get(3);


        // Randomly choose r1, r2, r3 to satisfy r1+r2+r3 = w^2((b − m + 1)r + r') + r''
        // = (b − m + 1)r
        BigInteger b_m_add_1_mult_r = b_m_add_1.multiply(r); // FIXME: mod p
        // = (b − m + 1)r + r'
        BigInteger b_m_add_1_mult_r_r_prime = b_m_add_1_mult_r.add(r_prime); // FIXME: mod p
        // = w^2((b − m + 1)r + r')
        BigInteger w2_b_m_add_1_mult_r_r_prime = w_squared.multiply(b_m_add_1_mult_r_r_prime); // FIXME: mod p
        // = w^2((b − m + 1)r + r') + r''
        BigInteger w2_b_m_add_1_mult_r_r_prime_r_prime_prime = w2_b_m_add_1_mult_r_r_prime.add(r_prime_prime); // FIXME: mod p

        // returns = r1,r2,r3
        List<BigInteger> rList = sampleRs(w2_b_m_add_1_mult_r_r_prime_r_prime_prime);
        BigInteger r1 = rList.get(0);
        BigInteger r2 = rList.get(1);
        BigInteger r3 = rList.get(2);

        // Compute c'_1, c'_2, c'_3
        BigInteger c_prime_1 = g.modPow(m1, p).multiply(h.modPow(r1, p)).mod(p);
        BigInteger c_prime_2 = g.modPow(m2, p).multiply(h.modPow(r2, p)).mod(p);
        BigInteger c_prime_3 = c_prime_prime.multiply(c_prime_1.modInverse(p)).multiply(c_prime_2.modInverse(p)).mod(p);

        // SQR2(m_4, r_3 | g, h | c'_3)
        SQRSecret secretSQR_2 = new SQRSecret(m4, r3);
        SQRStatement statementSQR_2 = new SQRStatement(g, h, c_prime_3, group);
        SQRProof proofSQR_2 = sigma2SQR.prove(statementSQR_2, secretSQR_2);


        /* ********
         * Step 5: Make non-interactive using Fiat-Shamir
         *********/
        BigInteger s = UTIL.getRandomElement(BigInteger.ONE, k1, random);               // Z_k1 \ {0}
        BigInteger t = UTIL.getRandomElement(BigInteger.ONE, k1, random);               // Z_k1 \ {0}
        // TODO: Change the above to hashed??


        /* ********
         * Step 6:
         *********/
        BigInteger x = s.multiply(m1).add(m2).add(m3);
        BigInteger y = m1.add(t.multiply(m2)).add(m3);
        BigInteger u = s.multiply(r1).add(r2).add(r3);
        BigInteger v = r1.add(t.multiply(r2)).add(r3);


        return new Sigma2Proof(stmntEL_0,
                statementSQR_1,
                statementSQR_2,
                proofEL_0,
                proofSQR_1,
                proofSQR_2,
                c1,c2,
                c_prime_prime,
                c_prime_1, c_prime_2, c_prime_3,
                s, t,
                x, y, u, v);
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

    private List<BigInteger> sampleMs(BigInteger upperBoundExclusive) {

        // Pick m4 randomly in [0;sqrt(bound)], ensuring that m3 is in [0;bound]
        BigInteger m4 = UTIL.getRandomElement(upperBoundExclusive.sqrt(), this.random);
        BigInteger m3 = m4.modPow(m4, upperBoundExclusive);

        BigInteger m1 = UTIL.getRandomElement(upperBoundExclusive, this.random);
        BigInteger m2 = upperBoundExclusive.subtract(m1).subtract(m3);

        BigInteger m1_m2_m3 = m1.add(m2).add(m3); //FIXME: Modulo!!!

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
        int check1 = c1.compareTo(c.multiply(g.modPow(a.subtract(BigInteger.ONE),p).modInverse(p)).mod(p));
        if (check1 != 0) { // compareTo returns 0 if the 2 BigIntegers are equal
            return false;
        }

        // c2 = g^{b+1} * c^{-1} mod p
        int check2 = c2.compareTo(g.modPow(b.add(BigInteger.ONE),p).multiply(c.modInverse(p)).mod(p));
        if (check2 != 0) {// compareTo returns 0 if the 2 BigIntegers are equal
            return false;
        }

        // c'' = c'_1 * c'_2 * c'_3 mod p
        int check3 = c_prime_prime.compareTo(c_prime_1.multiply(c_prime_2).multiply(c_prime_3).mod(p));
        if (check3 != 0) { // compareTo returns 0 if the 2 BigIntegers are equal
            return false;
        }

        // c'_1^s * c'_2 * c'_3 = g^x h^u mod p
        BigInteger check4Part1 = c_prime_1.modPow(s, p).multiply(c_prime_2).multiply(c_prime_3).mod(p);
        BigInteger check4Part2 = g.modPow(x, p).multiply(h.modPow(u,p)).mod(p);
        int check4 = check4Part1.compareTo(check4Part2);
        if (check4 != 0) { // compareTo returns 0 if the 2 BigIntegers are equal
            return false;
        }

        // c'_1 * c'_2^t * c'_3 = g^y h^v mod p
        BigInteger check5Part1 = c_prime_1.multiply(c_prime_2.modPow(t,p)).multiply(c_prime_3).mod(p);
        BigInteger check5Part2 = g.modPow(y, p).multiply(h.modPow(v,p)).mod(p);
        int check5 = check5Part1.compareTo(check5Part2);
        if (check5 != 0) { // compareTo returns 0 if the 2 BigIntegers are equal
            return false;
        }

        // x>0
        int check6 = x.compareTo(BigInteger.ZERO);
        if (check6 != 1) { // compareTo returns 1 if x>0
            return false;
        }

        // y>0
        int check7 = y.compareTo(BigInteger.ZERO);
        if (check7 != 1) { // compareTo returns 1 if y>0
            return false;
        }


        return true;
    }


}
