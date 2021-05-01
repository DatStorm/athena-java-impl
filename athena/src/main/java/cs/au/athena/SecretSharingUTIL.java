package cs.au.athena;

import cs.au.athena.dao.bulletinboard.DecryptionShareAndProof;
import cs.au.athena.dao.bulletinboard.Entry;
import cs.au.athena.dao.bulletinboard.PfPhase;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

import java.math.BigInteger;
import java.util.stream.Collectors;

public class SecretSharingUTIL {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("SecretSharing-UTIL");


    public static BigInteger computeDecryptionShare(Ciphertext ciphertext, ElGamalSK sk) {
        // d_i = c_1^{-P(i)}
        return ciphertext.c1.modPow(sk.toBigInteger().negate(), sk.pk.group.p);
//        return ciphertext.c1.modPow(sk.toBigInteger(), sk.pk.group.p).modInverse(sk.pk.group.p);
    }

    // For a single encryption
    public static BigInteger combineDecryptionShareAndDecrypt(Ciphertext ciphertext, List<BigInteger> shares, List<Integer> S, Group group) {
        int threshold = shares.size();

        // Combine shares
        BigInteger prod = BigInteger.ONE;
        for (int i = 0; i < threshold; i++) {
            BigInteger share = shares.get(i);
            int s = S.get(i);

            // Make lambda
            BigInteger lambda = Polynomial.getLambda(0, s, S, group).mod(group.q);

            // Perform lagrange interpolation
            prod = prod.multiply(share.modPow(lambda, group.p)).mod(group.p);
        }

        // Decrypt the ciphertext
        return ciphertext.c2.multiply(prod).mod(group.p);


    }

    // For a list of decryptions
    private static List<BigInteger> combineDecryptionShareAndDecrypt(List<Ciphertext> ciphertexts, List<Iterator<BigInteger>> shareIterators, List<Integer> S, Group group) {
        int threshold = S.size();

        List<BigInteger> plaintexts = new ArrayList<>();
        for (Ciphertext ciphertext : ciphertexts) {

            // Combine shares from each tallier using shareIterators
            BigInteger prodSumOfDecryptionShares = BigInteger.ONE;
            for (int i = 0; i < threshold; i++) {
                int s = S.get(i);
                BigInteger share = shareIterators.get(i).next();

                // Make lambda
                BigInteger lambda = Polynomial.getLambda(0, s, S, group).mod(group.q);

                // Perform lagrange interpolation
                prodSumOfDecryptionShares = prodSumOfDecryptionShares.multiply(share.modPow(lambda, group.p)).mod(group.p);
            }

            // Decrypt the ciphertext
            plaintexts.add(ciphertext.c2.multiply(prodSumOfDecryptionShares).mod(group.p));

        }

        return plaintexts;
    }


    public static List<BigInteger> combineDecryptionSharesAndDecrypt(List<Ciphertext> ciphertexts, PfPhase<DecryptionShareAndProof> completedPfPhase, Group group) {
        // Find the set of talliers in the pfr
        List<Integer> S = completedPfPhase.getEntries().stream()
                .map(Entry::getIndex)
                .collect(Collectors.toList());

        // Decrypt by combining decryption shares

        // We need to get k+1 decryption shares for each ballot.
        // Therefore we need to traverse the k+1 lists in pfr simultaneously
        // This is done by making an iterator for each tallier, and using calling each one time per ballot
        List<Iterator<BigInteger>> iterators = new ArrayList<>();
        for (Entry<DecryptionShareAndProof> entry : completedPfPhase.getEntries()) {
            Iterator<BigInteger> iterator = entry.getValues().stream()
                    .map(DecryptionShareAndProof::getShare)
                    .collect(Collectors.toList())
                    .iterator();

            iterators.add(iterator);
        }

        return combineDecryptionShareAndDecrypt(ciphertexts, iterators, S, group);
    }

    public static ElGamalSK combineSecretKeys(List<ElGamalSK> sks, List<Integer> S, Group group) {
        BigInteger sk = BigInteger.ZERO;
        for (int i = 0; i < sks.size(); i++) {
            ElGamalSK ski = sks.get(i);
            Integer s = S.get(i);
//            logger.info(MARKER, String.format("P%d :: ski=%d",s, ski.sk));

            int x = 0;
            BigInteger lambda = Polynomial.getLambda(x, s, S, group);
            logger.info(MARKER, String.format("lambda_%d(x=%d,s=%d,S=%s,group=..) = %d", i, x, s, S, lambda));
            sk = sk.add(ski.sk.multiply(lambda).mod(group.q)).mod(group.q);
        }

        return new ElGamalSK(group, sk);
    }
}
