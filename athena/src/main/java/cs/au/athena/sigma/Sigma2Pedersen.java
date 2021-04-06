package cs.au.athena.sigma;

import cs.au.athena.UTIL;
import cs.au.athena.dao.Sigma2Pedersen.Sigma2PedersenProof;
import cs.au.athena.dao.Sigma2Pedersen.Sigma2PedersenSecret;
import cs.au.athena.dao.Sigma2Pedersen.Sigma2PedersenStatement;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;

import java.math.BigInteger;
import java.util.Random;

public class Sigma2Pedersen {

    private final Random random;

    public Sigma2Pedersen(Random random) {
        this.random = random;
    }


    public Sigma2PedersenProof proveCipher(Ciphertext ciphertext, BigInteger r, BigInteger v, ElGamalPK pk) {
        BigInteger g1 = pk.h;
        BigInteger g2 = pk.group.g;
        BigInteger C = ciphertext.c2;
        Sigma2PedersenStatement statement = new Sigma2PedersenStatement(g1, g2, C, pk.group);

        BigInteger w1 = r;
        BigInteger w2 = v;

        Sigma2PedersenSecret secret = new Sigma2PedersenSecret(w1,w2);

        return prove(statement, secret);
    }

    private Sigma2PedersenProof prove(Sigma2PedersenStatement statement, Sigma2PedersenSecret secret) {
        // input C = g1^w1 * g2^w2
        BigInteger p = statement.group.p;
        BigInteger q = statement.group.q;

        // Choose r1 r2 in zq
        BigInteger r1 = UTIL.getRandomElement(q, this.random);
        BigInteger r2 = UTIL.getRandomElement(q, this.random);

        // Compute masking element
        // a = g1^r1 * g2^r2
        BigInteger a = statement.g1.modPow(r1, p).multiply(statement.g2.modPow(r2, p)).mod(p);

        // Compute challenge
        // e = hash(g1, g2, P, a)    in Zq
        BigInteger e = BigInteger.ZERO; //FIXME: yes. plz do HASH.hash()

        // Answer challenge
        BigInteger z1 = r1.add(e.multiply(secret.w2));
        BigInteger z2 = r2.add(e.multiply(secret.w1));

        return new Sigma2PedersenProof(a, z1, z2);
    }



    public boolean verifyCipher(Ciphertext ciphertext, Sigma2PedersenProof proof, ElGamalPK pk) {

        BigInteger g1 = pk.h;
        BigInteger g2 = pk.group.g;
        BigInteger C = ciphertext.c2;
        Sigma2PedersenStatement stmnt = new Sigma2PedersenStatement(g1, g2, C, pk.group);


        return verify(stmnt, proof);
    }

    private boolean verify(Sigma2PedersenStatement statement, Sigma2PedersenProof proof) {
        BigInteger p = statement.group.p;

        BigInteger e = BigInteger.ZERO; //FIXME: yes. plz do HASH.hash()

        // g1^z1 * g2^z2 = a * C^e
        BigInteger left = statement.g1.modPow(proof.z1, p).multiply(statement.g2.modPow(proof.z2, p)).mod(p);
        BigInteger right = proof.a.multiply(statement.C.modPow(e, p)).mod(p);

        return left.equals(right);
    }
}