package cs.au.athena.sigma;

import com.google.common.base.Strings;
import cs.au.athena.HASH;
import cs.au.athena.UTIL;
import cs.au.athena.dao.Sigma2Pedersen.Sigma2PedersenProof;
import cs.au.athena.dao.Sigma2Pedersen.Sigma2PedersenSecret;
import cs.au.athena.dao.Sigma2Pedersen.Sigma2PedersenStatement;
import cs.au.athena.dao.athena.UVector;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.Random;

public class Sigma2Pedersen {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("SIGMA-Sigma2Pedersen");
    private final Random random;


    public Sigma2Pedersen(Random random) {
        this.random = random;
    }

    public Sigma2PedersenProof proveCipher(Ciphertext ciphertext, BigInteger m, BigInteger r, UVector uvector, ElGamalPK pk) {
        BigInteger g = pk.group.g;
        BigInteger h = pk.h;
        BigInteger C = ciphertext.c2;
        Sigma2PedersenStatement statement = new Sigma2PedersenStatement(g, h, C, uvector, pk.group);
        Sigma2PedersenSecret secret = new Sigma2PedersenSecret(m, r);
        return prove(statement, secret);
    }

    // Prove that we know (m,r) S.T. C=g^m h^r
    private Sigma2PedersenProof prove(Sigma2PedersenStatement statement, Sigma2PedersenSecret secret) {
        // input C = g^m * h^r
        BigInteger p = statement.group.p;
        BigInteger q = statement.group.q;

        // Choose r1 r2 random in Z_q
        BigInteger r1 = UTIL.getRandomElement(q, this.random);
        BigInteger r2 = UTIL.getRandomElement(q, this.random);

        // Compute masking element
        // a = g^r1 * h^r2
        BigInteger a = statement.g.modPow(r1, p).multiply(statement.h.modPow(r2, p)).mod(p);

        // Compute challenge
        // e = hash(a, uvector)    in Zq
        BigInteger e = getChallenge(statement, a);
//        logger.info(MARKER, String.format("P.p: %s", p));
//        logger.info(MARKER, String.format("P.g: %s", statement.g));
//        logger.info(MARKER, String.format("P.h: %s", statement.h));
//        logger.info(MARKER, String.format("P.a: %s", a));

        // Answer challenge
        BigInteger z1 = r1.add(e.multiply(secret.m).mod(q)).mod(q);
        BigInteger z2 = r2.add(e.multiply(secret.r).mod(q)).mod(q);

//        logger.info(MARKER, String.format("P.z1: %s", z1));
//        logger.info(MARKER, String.format("P.z2: %s", z2));
//        logger.info(MARKER, String.format("P.C: %s", statement.C));

        return new Sigma2PedersenProof(a, z1, z2);
    }


    public static boolean verifyCipher(Ciphertext ciphertext, Sigma2PedersenProof proof, UVector uvector, ElGamalPK pk) {
        BigInteger g = pk.group.g;
        BigInteger h = pk.h;
        BigInteger C = ciphertext.c2;
        Sigma2PedersenStatement stmnt = new Sigma2PedersenStatement(g, h, C, uvector, pk.group);

        return verify(stmnt, proof);
    }

    private static boolean verify(Sigma2PedersenStatement statement, Sigma2PedersenProof proof) {
        BigInteger p = statement.group.p;
        BigInteger g = statement.g;
        BigInteger h = statement.h;
        BigInteger a = proof.a;

        // Compute challenge
        // e = hash(a, uvector)  in Zq
        BigInteger e = getChallenge(statement, a);
//        logger.info(MARKER, String.format("V.p: %s", p));
//        logger.info(MARKER, String.format("V.g: %s", g));
//        logger.info(MARKER, String.format("V.h: %s", h));
//        logger.info(MARKER, String.format("V.a: %s", a));
//
//        logger.info(MARKER, String.format("V.z1: %s", proof.z1));
//        logger.info(MARKER, String.format("V.z2: %s", proof.z2));
//        logger.info(MARKER, String.format("V.C: %s", statement.C));

        // g^z1 * h^z2 = a * C^e
        BigInteger left = g.modPow(proof.z1, p).multiply(h.modPow(proof.z2, p)).mod(p);
        BigInteger right = a.multiply(statement.C.modPow(e, p)).mod(p);

        return left.equals(right);
    }

    private static BigInteger getChallenge(Sigma2PedersenStatement statement, BigInteger a) {
        BigInteger hashed = HASH.hashToBigInteger(statement.uvector, a);
        long seed = hashed.longValue();

        return UTIL.getRandomElement(statement.group.q, new Random(seed));
    }



}