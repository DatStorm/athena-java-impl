package project.athena;

import com.google.common.primitives.Bytes;
import project.UTIL;
import project.dao.sigma3.ProveDecryptionInfo;
import project.dao.sigma3.PublicInfoSigma3;
import project.elgamal.CipherText;
import project.elgamal.ElGamalSK;

import java.io.File;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class Sigma3 {


    private MessageDigest hashH;

    public Sigma3(MessageDigest hashH) {
        this.hashH = hashH;
    }

    // (pk, c', N), sk, k)
    // prove h=g^sk  ===  m^sk
    public PublicInfoSigma3 proveDecryption(ProveDecryptionInfo info, ElGamalSK sk, int k) {
        Random random = new SecureRandom();

        BigInteger g = info.pk.getGroup().getG();
        BigInteger p = info.pk.getGroup().getP();
        BigInteger q = info.pk.getGroup().getQ();
        BigInteger h = info.pk.getH();

        BigInteger m = info.plainText;

        //Step 1
        BigInteger s = UTIL.getRandomElement(BigInteger.ZERO, q, random);
        BigInteger a = g.modPow(s, p);
        BigInteger b = m.modPow(s, p);


        CipherText cipherText = info.cipherText;
        BigInteger c1 = cipherText.c1;
        BigInteger c2 = cipherText.c2;
        BigInteger z = c2.multiply(m.modInverse(p)); //c1^sk


        //Step 2
        BigInteger c = hash(a, b, g, h, z, c1, c2);
        BigInteger r = s.add(c.multiply(sk.toBigInteger())); //r = s + c*sk

        return new PublicInfoSigma3(a, b, r);
    }

    private BigInteger hash(BigInteger a, BigInteger b, BigInteger g, BigInteger h, BigInteger z, BigInteger c1, BigInteger c2) {

        byte[] bytes_a = a.toByteArray();
        byte[] bytes_b = b.toByteArray();
        byte[] bytes_g = g.toByteArray();
        byte[] bytes_h = h.toByteArray();
        byte[] bytes_z = z.toByteArray();
        byte[] bytes_c1 = c1.toByteArray();
        byte[] bytes_c2 = c2.toByteArray();
        byte[] concatenated = Bytes.concat(bytes_a, bytes_b, bytes_g, bytes_h, bytes_z, bytes_c1, bytes_c2);
        byte[] hashed = this.hashH.digest(concatenated);
        return new BigInteger(hashed);
    }

    public boolean verifyDecryption(ProveDecryptionInfo info, PublicInfoSigma3 publicInfo, int k) {
        // for check part1
        BigInteger g = PublicInfoSigma3.;
        BigInteger p = null;
        BigInteger h;
        BigInteger a;

        // for check part2
        BigInteger z;
        BigInteger b;
        BigInteger c1;
        BigInteger c2;

        BigInteger c = hash(a, b, g, h, z, c1, c2);
        BigInteger r = BigInteger.ONE;

        boolean checkPart1 = checkPart1(g, r, a, h, c,p);
        boolean checkPart2 = checkPart2(c1, r, b, z, c,p);

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