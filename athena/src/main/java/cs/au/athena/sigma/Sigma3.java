package cs.au.athena.sigma;

import com.google.common.primitives.Bytes;
import cs.au.athena.HASH;
import cs.au.athena.UTIL;
import cs.au.athena.dao.sigma3.Sigma3Statement;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Sigma3 {

    public Sigma3() {    }

    private static void d(String s) {
//        System.out.println("Sigma3: " + s);
    }

    // prove that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/m
    /**
    * param plaintextElement: A group element representing the plaintext. g^m
    *
    */
    public Sigma3Proof proveDecryption(Ciphertext ciphertext, BigInteger plaintextElement, ElGamalSK sk, int kappa) {
        return proveLogEquality(createStatement(sk.pk, ciphertext, plaintextElement), sk.toBigInteger(), kappa);
    }

    public Sigma3Proof proveDecryption(Sigma3Statement statement, BigInteger secret, int kappa) {
        return proveLogEquality(statement, secret, kappa);
    }

    public boolean verifyDecryption(Ciphertext ciphertext, BigInteger plaintextElement, ElGamalPK pk, Sigma3Proof decProof, int kappa) {
        return verifyLogEquality(createStatement(pk, ciphertext, plaintextElement), decProof, kappa);
    }

    public boolean verifyDecryption(Sigma3Statement statement, Sigma3Proof decProof, int kappa) {
        return verifyLogEquality(statement, decProof, kappa);
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

        byte[] hashed = HASH.hash(concatenated);
        return new BigInteger(1,hashed);
    }


    /**
     *
     * @param pk
     * @param ciphertext
     * @param plaintextElement: the group element representing the value. g^m
     * @return
     */
    public static Sigma3Statement createStatement(ElGamalPK pk, Ciphertext ciphertext, BigInteger plaintextElement) {
        BigInteger p = pk.getGroup().getP();
        BigInteger g = pk.getGroup().getG();

        // prove that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/g^m
        BigInteger alpha = pk.getH();
        BigInteger alpha_base = pk.getGroup().getG();
        
        // beta = c2 * g^(plain)^{-1} mod p 
        // c2/g^m = h^r g^m * g^-m
        BigInteger beta = ciphertext.c2.multiply(plaintextElement.modInverse(p)).mod(p);
        BigInteger beta_base = ciphertext.c1;

        return new Sigma3Statement(pk.getGroup(), alpha, beta, alpha_base, beta_base);
    }


    public boolean checkPart1(BigInteger alpha_base, BigInteger r, BigInteger a, BigInteger alpha, BigInteger c, BigInteger p) {
        BigInteger alpha_base_r = alpha_base.modPow(r, p);
        BigInteger a_alpha_c = a.multiply(alpha.modPow(c,p)).mod(p);
        d("check1: alpha_base_r=  " + alpha_base_r);
        d("check1: a_alpha_c=     " + a_alpha_c);
        return alpha_base_r.compareTo(a_alpha_c) == 0;
    }
    

    public boolean checkPart2(BigInteger beta_base, BigInteger r, BigInteger b, BigInteger beta, BigInteger c, BigInteger p) {
        BigInteger beta_base_r = beta_base.modPow(r,p);

        BigInteger b_beta_c = b.multiply(beta.modPow(c,p)).mod(p);
        d("check2: beta_base_r=   " + beta_base_r);
        d("check2: b_beta_c=      " + b_beta_c);
        return beta_base_r.compareTo(b_beta_c) == 0;
    }


}