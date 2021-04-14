package cs.au.athena;

import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class GENERATOR {
    private static final List<BigInteger> usedNonces = new ArrayList<>();

    private GENERATOR() {}

    public static List<List<BigInteger>> generateRangeProofGenerators(ElGamalPK pk, int nc) {

        // Calculate ranges for range proofs
        BigInteger H = BigInteger.valueOf(nc - 1); // H = nc - 1
        int n1 = Bulletproof.getN(H);

        // Generate a common seed from the public key
        byte[] hashSeed = HASH.hash(pk.h.toByteArray());
        Random seed = new Random(new BigInteger(hashSeed).longValue());

        // Use the seed to generate generators
        List<BigInteger> g_vector_vote = pk.group.newGenerators(n1, seed);
        List<BigInteger> h_vector_vote = pk.group.newGenerators(n1, seed);

        // Return generators
        return Arrays.asList(g_vector_vote, h_vector_vote);
    }

    public static BigInteger generateUniqueNonce(BigInteger from, BigInteger end, Random random) {
        // Sample nonce
        BigInteger nonce = UTIL.getRandomElement(from, end, random);

        // Sample again while the nonce is not unique
        while (usedNonces.contains(nonce)) {
            nonce = UTIL.getRandomElement(from, end, random);
        };

        // We found a unique nonce, store and return
        usedNonces.add(nonce);
        return nonce;
    }
}
