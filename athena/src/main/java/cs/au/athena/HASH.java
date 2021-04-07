package cs.au.athena;

import com.google.common.primitives.Bytes;
import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.athena.UVector;
import cs.au.athena.dao.mixnet.MixBallot;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

public class HASH {
    private static final MessageDigest hashH = GET_HASH_FUNCTION();

    private static MessageDigest GET_HASH_FUNCTION() {
        MessageDigest sha3_256 = null;
        try {
            sha3_256 = MessageDigest.getInstance(CONSTANTS.ALGORITHM_SHA3_256);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return sha3_256;
    }


    public static List<Boolean> computeChallenges(int length, List<List<MixBallot>> ballots) {
        byte[] data = serialize(ballots);
        byte[] hash = hash(data);

        List<Boolean> challenges = new ArrayList<>(length);
        BitSet bitSet = BitSet.valueOf(hash);

        for(int i = 0; i < length; i++) {
            challenges.add(i, bitSet.get(i));
        }

        return challenges;
    }

    //https://stackoverflow.com/questions/3736058/java-object-to-byte-and-byte-to-object-converter-for-tokyo-cabinet/3736091
    public static byte[] serialize(List<List<MixBallot>> ballots) {
       byte[] concatenated = new byte[]{};

        // \mathcal{B}_j for j in [1,kappa]
        for (List<MixBallot> shadowMix : ballots) {
            for (MixBallot mixBallot : shadowMix) {
                concatenated = Bytes.concat(concatenated, mixBallot.toByteArray());
            }
        }

        return concatenated;
    }


    public static byte[] hash(byte[] bytes) {
        return hashH.digest(bytes);
    }


    public static BigInteger hashToBigInteger(UVector vectorU, BigInteger... values) {
        byte[] concatenated = new byte[]{};


        concatenated = Bytes.concat(concatenated, vectorU.toByteArray());

        for (BigInteger bigInt : values) {
            concatenated = Bytes.concat(concatenated, bigInt.toByteArray());
        }


        byte[] hashed = hash(concatenated);

        // create positive long value.
        return new BigInteger(1, hashed);
    }

    //Hash
    public static byte[] truncateHash(byte[] hash, int length){
        if (hash.length < length) {
            // this should not occur
            throw new RuntimeException("The hash should not be smaller than the specified length");
        }
        return Arrays.copyOf(hash, length);
    }
}
