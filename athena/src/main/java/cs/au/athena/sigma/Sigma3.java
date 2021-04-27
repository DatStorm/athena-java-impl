package cs.au.athena.sigma;

import com.google.common.primitives.Bytes;
import cs.au.athena.HASH;
import cs.au.athena.UTIL;
import cs.au.athena.dao.sigma3.Sigma3Statement;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Sigma3 {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("Sigma3: ");

    public Sigma3() {    }


    public Sigma3Proof proveDecryption(Ciphertext ciphertext, BigInteger plaintextElement, ElGamalSK sk, int kappa) {
        Sigma3Statement statement = createDecryptionStatement(ciphertext, plaintextElement, sk.pk);
        return proveLogEquality(statement, sk.toBigInteger(), kappa);
    }

    public boolean verifyDecryption(Ciphertext ciphertext, BigInteger decryptionShare, Sigma3Proof decProof, ElGamalPK pk, int kappa) {
        Sigma3Statement statement = createDecryptionStatement(ciphertext, decryptionShare, pk);
        return verifyLogEquality(statement, decProof, kappa);
    }



    // FIXME: Test this
    public Sigma3Proof proveDecryptionShare(Ciphertext ciphertext, BigInteger decryptionShare, ElGamalSK sk, int kappa) {
        Sigma3Statement statement = createDecryptionShareStatement(ciphertext, decryptionShare, sk.pk);
        Sigma3Proof proof = proveLogEquality(statement, sk.sk, kappa);

//        assert verifyDecryptionShare(ciphertext, decryptionShare, proof, sk.pk, kappa): String.format("Verification of share failed. ");

        return proof;
    }

    // FIXME: Test this
    public boolean verifyDecryptionShare(Ciphertext ciphertext, BigInteger plaintextElement, Sigma3Proof decProof, ElGamalPK pk, int kappa) {
        Sigma3Statement statement = createDecryptionShareStatement(ciphertext, plaintextElement, pk);
        return verifyLogEquality(statement, decProof, kappa);
    }









    /**
     *
     * @param ciphertext
     * @param plaintextElement : the group element representing the value. g^m
     * @param pk
     * @return
     */
    public static Sigma3Statement createDecryptionStatement(Ciphertext ciphertext, BigInteger plaintextElement, ElGamalPK pk) {
        Group group = pk.group;

        // prove that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/g^m
        BigInteger alpha_base = pk.group.g;
        BigInteger alpha = pk.h;

        // beta = c2 * g^(plain)^{-1} mod p 
        // c2/g^m = h^r g^m * g^-m
        BigInteger beta_base = ciphertext.c1;
        BigInteger beta = ciphertext.c2.multiply(plaintextElement.modInverse(group.p)).mod(group.p);

        return new Sigma3Statement(pk.getGroup(), alpha, beta, alpha_base, beta_base);
    }

    public Sigma3Statement createDecryptionShareStatement(Ciphertext ciphertext, BigInteger decryptionShare, ElGamalPK pk) {
        Group group = pk.group;

        // Check that h_j = g^{P(j)} and log_g h_j = log_c1 d_j^-1
        BigInteger alpha_base = group.g;
        BigInteger alpha = pk.h;
        BigInteger beta_base = ciphertext.c1;
        BigInteger beta = decryptionShare.modInverse(group.p);

        return new Sigma3Statement(group, alpha, beta, alpha_base, beta_base);
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

    public boolean checkPart1(BigInteger alpha_base, BigInteger r, BigInteger a, BigInteger alpha, BigInteger c, BigInteger p) {
        BigInteger alpha_base_r = alpha_base.modPow(r, p);
        BigInteger a_alpha_c = a.multiply(alpha.modPow(c,p)).mod(p);

        return alpha_base_r.compareTo(a_alpha_c) == 0;
    }
    

    public boolean checkPart2(BigInteger beta_base, BigInteger r, BigInteger b, BigInteger beta, BigInteger c, BigInteger p) {
        BigInteger beta_base_r = beta_base.modPow(r,p);

        BigInteger b_beta_c = b.multiply(beta.modPow(c,p)).mod(p);

        return beta_base_r.compareTo(b_beta_c) == 0;
    }
}