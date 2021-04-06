package project;

import elgamal.ElGamalPK;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class GENERATOR {

    public static List<List<BigInteger>> generateRangeProofGenerators(ElGamalPK pk, int nc) {

        // Calculate ranges for range proofs
        BigInteger H = BigInteger.valueOf(nc - 1); // H = nc - 1
        int n1 = Bulletproof.getN(H);
        int n2 = Bulletproof.getN(pk.group.q) - 1; //q.bitlength()-1

        // Generate a common seed from the public key
        byte[] hashSeed = HASH.hash(pk.h.toByteArray());
        Random seed = new Random(new BigInteger(hashSeed).longValue());

        // Use the seed to generate generators
        List<BigInteger> g_vector_vote = pk.group.newGenerators(n1, seed);
        List<BigInteger> h_vector_vote = pk.group.newGenerators(n1, seed);
        List<BigInteger> g_vector_negatedPrivateCredential = pk.group.newGenerators(n2, seed);
        List<BigInteger> h_vector_negatedPrivateCredential = pk.group.newGenerators(n2, seed);

        // Return generators
        return Arrays.asList(
                g_vector_vote,
                h_vector_vote,
                g_vector_negatedPrivateCredential,
                h_vector_negatedPrivateCredential);
    }
}
