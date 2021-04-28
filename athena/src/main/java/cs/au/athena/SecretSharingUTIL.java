package cs.au.athena;

import cs.au.athena.dao.bulletinboard.DecryptionShareAndProof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

import java.math.BigInteger;

public class SecretSharingUTIL {

    public static BigInteger computeDecryptionShare(Ciphertext ciphertext, ElGamalSK sk) {
        return ciphertext.c1.modPow(sk.toBigInteger().negate(), sk.pk.group.p);
    }


    public static BigInteger combineDecryptionShareAndDecrypt(Ciphertext ciphertext, List<BigInteger> shares, List<Integer> S, Group group) {
        int threshold = shares.size();

        // Combine shares
        BigInteger prodSumOfDecryptionShares = BigInteger.ONE;
        for (int i = 0; i < threshold; i++) {
            BigInteger share = shares.get(i);
            int s = S.get(i);

            // Make lambda
            BigInteger lambda = Polynomial.getLambda(0, s, S).mod(group.q);

            // Perform lagrange interpolation
            prodSumOfDecryptionShares = prodSumOfDecryptionShares.multiply(share.modPow(lambda, group.p)).mod(group.p);
        }

        // Decrypt the ciphertext
        BigInteger plaintextElement = ciphertext.c2.multiply(prodSumOfDecryptionShares).mod(group.p);
        return plaintextElement;
    }

    /*

    public static BigInteger combineDecryptionShare2(Ciphertext ciphertext, List<Iterator<BigInteger>> shareIterators, List<Integer> S, Group group) {
        int threshold = S.size();

        // Combine shares
        BigInteger prodSumOfDecryptionShares = BigInteger.ONE;
        for (int i = 0; i < threshold; i++) {
            BigInteger share = shareIterators.get(i).next();
            int s = S.get(i);

            // Make lambda
            BigInteger lambda = Polynomial.getLambda(0, s, S).mod(group.q);

            // Perform lagrange interpolation
            prodSumOfDecryptionShares = prodSumOfDecryptionShares.multiply(share.modPow(lambda, group.p)).mod(group.p);
        }

        // Decrypt the ciphertext
        BigInteger plaintextElement = ciphertext.c2.multiply(prodSumOfDecryptionShares).mod(group.p);
        return plaintextElement;
    }

     */


}
