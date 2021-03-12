package project.sigma;

import com.google.common.primitives.Bytes;
import project.UTIL;
import project.dao.sigma3.Sigma3Statement;
import project.dao.sigma3.Sigma3Proof;
import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class Sigma3 {
    private MessageDigest hashH;

    public Sigma3(MessageDigest hashH) {
        this.hashH = hashH;
    }

    private static void d(String s) {
//        System.out.println("Sigma3: " + s);
    }

    // prove that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/m
    public Sigma3Proof proveDecryption(CipherText ciphertext, BigInteger plaintext, ElGamalSK sk, int kappa) {
        return proveLogEquality(createStatement(sk.pk, ciphertext, plaintext), sk.toBigInteger(), kappa);
    }

    public Sigma3Proof proveDecryption(Sigma3Statement statement, BigInteger secret, int kappa) {
        return proveLogEquality(statement, secret, kappa);
    }



    public boolean verifyDecryption(CipherText ciphertext, BigInteger plaintext, ElGamalPK pk, Sigma3Proof decProof, int kappa) {
        return verifyLogEquality(createStatement(pk,ciphertext,plaintext), decProof, kappa);
    }

    // log_{alpha_base} alpha = log_{beta_base} beta}
    public Sigma3Proof proveLogEquality(Sigma3Statement statement, BigInteger secret, int kappa) {
        Random random = new SecureRandom();
        BigInteger p = statement.group.p;
        BigInteger q = statement.group.q;

        BigInteger alpha = statement.alpha;
        BigInteger beta = statement.beta;
        BigInteger alpha_base = statement.alpha_base;
        BigInteger beta_base = statement.beta_base;

        //Step 1
        BigInteger s = UTIL.getRandomElement(BigInteger.ZERO, q, random);

        BigInteger a = alpha_base.modPow(s, p);
        BigInteger b = beta_base.modPow(s, p);

        //Step 2-3
        BigInteger c = hash(a, b, alpha, beta, alpha_base, beta_base);

        BigInteger alpha_c = c.multiply(secret).mod(q);
        BigInteger r = s.add(alpha_c).mod(q); //r = s + c*secret

        d("prove.check1: " + checkPart1(alpha_base, r, a, alpha, c, p));
        d("prove.check2: " + checkPart2(beta_base,  r, b, beta,  c, p));

        // ProveDecryption
        return new Sigma3Proof(a, b, r);
    }

    public boolean verifyLogEquality(Sigma3Statement statement, Sigma3Proof decProof, int kappa) {
        if(decProof.isEmpty()){
            System.err.println("Sigma3.verifyLogEquality=> decProof is empty");
        }
        
        BigInteger p = statement.group.p;

        // verify that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/m
        BigInteger alpha = statement.alpha;
        BigInteger beta = statement.beta;
        BigInteger alpha_base = statement.alpha_base;
        BigInteger beta_base = statement.beta_base;

        BigInteger a = decProof.a;
        BigInteger b = decProof.b;

        BigInteger c = hash(a, b, alpha, beta, alpha_base, beta_base);
        BigInteger r = decProof.r;

        boolean checkPart1 = checkPart1(alpha_base, r, a, alpha, c, p);
        boolean checkPart2 = checkPart2(beta_base,  r, b, beta,  c, p);

        d("verify.check1: " + checkPart1);
        d("verify.check2: " + checkPart2);

        return checkPart1 && checkPart2;
    }





    public BigInteger hash(BigInteger ... values) {
        byte[] concatenated = new byte[]{};
        for (BigInteger integer : values) {
            concatenated = Bytes.concat(concatenated, integer.toByteArray());
        }

        byte[] hashed = this.hashH.digest(concatenated);
        return new BigInteger(1,hashed);
    }


    /**
     *
     * @param pk
     * @param cipher
     * @param plain
     * @return
     */
    public static Sigma3Statement createStatement(ElGamalPK pk, CipherText cipher, BigInteger plain) {
        BigInteger p = pk.getGroup().getP();
        BigInteger g = pk.getGroup().getG();

        // prove that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/g^m
        BigInteger alpha = pk.getH();
        BigInteger beta = cipher.c2.multiply(g.modPow(plain,p).modInverse(p)).mod(p);
        BigInteger alpha_base = pk.getGroup().getG();
        BigInteger beta_base = cipher.c1;

        return new Sigma3Statement(pk.getGroup(), alpha, beta, alpha_base, beta_base);
    }


    public boolean checkPart1(BigInteger g, BigInteger r, BigInteger a, BigInteger h, BigInteger c, BigInteger p) {
        BigInteger gr = g.modPow(r, p);
        BigInteger ahc = a.multiply(h.modPow(c,p)).mod(p);
        d("p1: gr=" + gr + ", ahc="+ ahc);
        return gr.compareTo(ahc) == 0;
    }
    

    public boolean checkPart2(BigInteger c1, BigInteger r, BigInteger b, BigInteger z, BigInteger c, BigInteger p) {
        BigInteger c1_r = c1.modPow(r,p);
        BigInteger bz_c = b.multiply(z.modPow(c,p)).mod(p);
        d("p2: c1_r=" + c1_r + ", bz_c="+ bz_c);
        return c1_r.compareTo(bz_c) == 0;
    }


}