package project.athena;

import com.google.common.primitives.Bytes;
import project.UTIL;
import project.dao.sigma3.PublicInfoSigma3;
import project.dao.sigma3.DecryptionProof;
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

    public DecryptionProof proveLogEquality(PublicInfoSigma3 info, ElGamalSK sk, int kappa) {
        Random random = new SecureRandom();
        BigInteger p = info.group.p;
        BigInteger q = info.group.q;

        BigInteger alpha = info.alpha;
        BigInteger beta = info.beta;
        BigInteger alpha_base = info.alpha_base;
        BigInteger beta_base = info.beta_base;

        //Step 1
        BigInteger s = UTIL.getRandomElement(BigInteger.ZERO, q, random);

        BigInteger a = alpha_base.modPow(s, p);
        BigInteger b = beta_base.modPow(s, p);

        //Step 2-3
        BigInteger c = hash(a, b, alpha, beta, alpha_base, beta_base, beta_base); // FIXME::: MAKRK's (m,m)

        BigInteger alpha_c = c.multiply(sk.toBigInteger()).mod(q);
        BigInteger r = s.add(alpha_c).mod(q); //r = s + c*sk

        // ProveDecryptionInfo
        return new DecryptionProof(a, b, r);
    }

    // (pk, c', N), sk, k)
    // prove h=g^sk  ===  m^sk
    public DecryptionProof proveDecryption(PublicInfoSigma3 info, ElGamalSK sk, int kappa) {
        Random random = new SecureRandom();

        BigInteger g = info.pk.getGroup().getG();
        BigInteger p = info.pk.getGroup().getP();
        BigInteger q = info.pk.getGroup().getQ();
        BigInteger h = info.pk.getH();

        BigInteger c1 = info.cipherText.c1;

        BigInteger m = info.plainText;
        BigInteger c2 = info.cipherText.c2;

        //Step 1
        BigInteger s = UTIL.getRandomElement(BigInteger.ZERO, q, random);

        BigInteger a = g.modPow(s, p);
        BigInteger b = c1.modPow(s, p);

        BigInteger z = c2.multiply(m.modInverse(p)).mod(p); //c1^sk = c2/m


        //Step 2-3
        BigInteger c = hash(a, b, g, h, z, c1, c2);

        BigInteger alpha_c = c.multiply(sk.toBigInteger()); // .mod(p) ???
        BigInteger r = s.add(alpha_c).mod(q); //r = s + c*sk

        // ProveDecryptionInfo
        return new DecryptionProof(a, b, r);
    }

    // prove that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/m
    public DecryptionProof proveDecryptionNew(CipherText ciphertext, BigInteger plaintext, ElGamalSK sk, int kappa) {
        ElGamalPK pk = sk.getPK();
        BigInteger p = pk.getGroup().getP();

        // prove that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/m
        BigInteger alpha = pk.getH();
        BigInteger beta = ciphertext.c2.multiply(plaintext.modInverse(p)).mod(p);
        BigInteger alpha_base = pk.getGroup().getG();
        BigInteger beta_base = ciphertext.c1;

        PublicInfoSigma3 statement = new PublicInfoSigma3(pk.getGroup(), alpha, beta, alpha_base, beta_base);

        return proveLogEquality(statement, sk, kappa);
    }
    

    public BigInteger hash(BigInteger a, BigInteger b, BigInteger g, BigInteger h, BigInteger z, BigInteger c1, BigInteger c2) {

        byte[] bytes_a = a.toByteArray();
        byte[] bytes_b = b.toByteArray();
        byte[] bytes_g = g.toByteArray();
        byte[] bytes_h = h.toByteArray();
        byte[] bytes_z = z.toByteArray();
        byte[] bytes_c1 = c1.toByteArray();
        byte[] bytes_c2 = c2.toByteArray();
        byte[] concatenated = Bytes.concat(bytes_a, bytes_b, bytes_g, bytes_h, bytes_z, bytes_c1, bytes_c2);
        byte[] hashed = this.hashH.digest(concatenated);
        return new BigInteger(1,hashed);
    }

    public boolean verifyDecryption(PublicInfoSigma3 info, DecryptionProof decProof, int kappa) {
        // for check part1
        BigInteger g = info.pk.getGroup().getG();
        BigInteger p = info.pk.getGroup().getP();
        BigInteger h = info.pk.getH();

        // for check part2
        BigInteger c1 = info.cipherText.c1;
        BigInteger c2 = info.cipherText.c2;
        BigInteger z = c2.multiply(info.plainText.modInverse(p)).mod(p); //c1^sk = c2/m

        BigInteger a = decProof.a;
        BigInteger b = decProof.b;

        BigInteger c = hash(a, b, g, h, z, c1, c2);
        BigInteger r = decProof.r;

        boolean checkPart1 = checkPart1(g, r, a, h, c,p);
        boolean checkPart2 = checkPart2(c1, r, b, z, c,p);

        return checkPart1 && checkPart2;
    }

    public boolean verifyDecryptionNew(CipherText ciphertext, BigInteger plaintext, ElGamalPK pk, DecryptionProof decProof, int kappa) {
        BigInteger p = pk.getGroup().getP();

        // prove that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/m
        BigInteger alpha = pk.getH();
        BigInteger beta = ciphertext.c2.multiply(plaintext.modInverse(p)).mod(p);
        BigInteger alpha_base = pk.getGroup().getG();
        BigInteger beta_base = ciphertext.c1;

        PublicInfoSigma3 statement = new PublicInfoSigma3(pk.getGroup(), alpha, beta, alpha_base, beta_base);

        return verifyLogEquality(statement, decProof, kappa);
    }

    public boolean verifyLogEquality(PublicInfoSigma3 info, DecryptionProof decProof, int kappa) {
        BigInteger p = info.group.p;

        // verify that log_g g^sk = log_c1 c1^sk aka log_g h = log_c1 c2/m
        BigInteger alpha = info.alpha;
        BigInteger beta = info.beta;
        BigInteger alpha_base = info.alpha_base;
        BigInteger beta_base = info.beta_base;

        BigInteger a = decProof.a;
        BigInteger b = decProof.b;

        BigInteger c = hash(a, b, alpha, beta, alpha_base, beta_base, beta_base);
        BigInteger r = decProof.r;

        boolean checkPart1 = checkPart1(alpha_base, r, a, alpha, c, p);
        boolean checkPart2 = checkPart2(beta_base,  r, b, beta,  c, p);

        return checkPart1 && checkPart2;
    }

    public boolean checkPart1(BigInteger g, BigInteger r, BigInteger a, BigInteger h, BigInteger c, BigInteger p) {
        BigInteger gr = g.modPow(r, p);
        BigInteger ahc = a.multiply(h.modPow(c,p)).mod(p);
        return gr.compareTo(ahc) == 0;
    }

    public boolean checkPart2(BigInteger c1, BigInteger r, BigInteger b, BigInteger z, BigInteger c, BigInteger p) {
        BigInteger c1_r = c1.modPow(r,p);
        BigInteger bz_c = b.multiply(z.modPow(c,p)).mod(p);
        return c1_r.compareTo(bz_c) == 0;
    }
}