package project.sigma.sigma2;

import project.UTIL;
import project.dao.sigma2.*;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.ElGamalPK;
import project.elgamal.Group;
import project.factory.Factory;

import java.math.BigInteger;
import java.security.MessageDigest;
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
    private final BigInteger k1 = BigInteger.valueOf(320); // k1 << k2   // TODO: CHANGE
    private final BigInteger k2 = BigInteger.valueOf(1500); // 3000    // TODO: CHANGE
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
        BigInteger r_prime = UTIL.getRandomElement(k2, random);

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
        BigInteger m1 = null;
        BigInteger m2 = null;
        BigInteger m4 = null;


        // Randomly choose r1, r2, r3 to satisfy r1+r2+r3 = w^2((b − m + 1)r + r') + r''
        BigInteger r1 = null;
        BigInteger r2 = null;
        BigInteger r3 = null;

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



        /* ********
         * Step 6:
         *********/


        return new Sigma2Proof(proofEL_0, proofSQR_1, proofSQR_2);
    }


    /* ********
     * Step 7:
     *********/
    public boolean verifyCipher(Sigma2Statement statement, Sigma2Proof proof) {


        return true;
    }


}
