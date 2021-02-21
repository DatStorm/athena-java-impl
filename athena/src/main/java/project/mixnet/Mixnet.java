package project.mixnet;

import com.google.common.primitives.Bytes;
import project.CONSTANTS;
import project.UTIL;
import project.dao.mixnet.*;
import project.elgamal.CipherText;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.factory.Factory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

public class Mixnet {
    //    private final int n = CONSTANTS.MIXNET_N;
    private final int n = 2;
    private final MessageDigest hashH;
    private final ElGamal elgamal;
    private final Random random;
    private final ElGamalPK pk;


    public Mixnet(Factory factory) {
        this.hashH = factory.getHash();
        this.elgamal = factory.getElgamal();
        this.random = factory.getRandom();
        this.pk = factory.getPK();

    }


    public MixnetProof proveMix(MixnetStatement stmt) {

        List<MixBallot> listOfB = stmt.getB();
        int ell = listOfB.size();

        /* *******************
         * Step 1
         *********************/
        Step1Statement step1Stmnt = step1(listOfB, ell);
        List<MixBallot> listOfBj_prime = step1Stmnt.getListOfBi_prime();

        /* *******************
         * Step 2
         *********************/
        Step2Statement step2Stmnt = step2(listOfBj_prime);
        List<MixBallot> Bcal_prime = step2Stmnt.getPermutedBallots();


        /* *******************
         * Step 3
         *********************/
        Map<Integer, List<MixBallot>> mapOfBj = new HashMap<>(n);
        List<Step1Statement> listOfStep1StmtBj = new ArrayList<>(n);
        List<Step2Statement> listOfStep2StmtBj = new ArrayList<>(n);
        for (int j = 1; j <= n; j++) {
            Step1Statement step1_j_stmnt = step1(listOfB, ell);
            listOfStep1StmtBj.add(step1_j_stmnt);

            List<MixBallot> listOfReencMixBallots = step1_j_stmnt.getListOfBi_prime();
            Step2Statement step2_j_stmnt = step2(listOfReencMixBallots);
            listOfStep2StmtBj.add(step2_j_stmnt);

            List<MixBallot> listOfPermuttedMixBallots = step2_j_stmnt.getPermutedBallots();
            mapOfBj.put(j, listOfPermuttedMixBallots);
        }


        /* *******************
         * Step 4
         *********************/
        List<Boolean> listOfCs = hash(mapOfBj);
        List<BigInteger> reencDataBjRandomnessR = new ArrayList<>();
        List<BigInteger> reencDataBjRandomnessS = new ArrayList<>();
        List<Integer> permDataBj;
        Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessR = new HashMap<>();
        Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessS = new HashMap<>();
        Map<Integer, List<Integer>> mapOfPermDataBj = new HashMap<>();

        for (int j = 1; j <= n; j++) {
            Boolean challengej = listOfCs.get(j - 1);
            // Get reenc and perm data used to create B'
            List<BigInteger> randROfBj = listOfStep1StmtBj.get(j - 1).getListOfRandR();
            List<BigInteger> randSOfBj = listOfStep1StmtBj.get(j - 1).getListOfRandS();
            List<Integer> piOfBj = listOfStep2StmtBj.get(j - 1).getPermutation();

            if (challengej) {// challenge c = 1
                // Get reenc and perm data used to create B'
                List<BigInteger> randROfB_prime = step1Stmnt.getListOfRandR();
                List<BigInteger> randSOfB_prime = step1Stmnt.getListOfRandS();
                List<Integer> piOfB_prime = step2Stmnt.getPermutation();

                // Compute composed permutation pi2^-1 o pi1
                // composed permutation pi'_j, composition of permutation used to create Bj and B'
                List<Integer> shadowPermutationInverse = UTIL.inversePermutation(piOfBj);
                permDataBj = UTIL.composePermutation(shadowPermutationInverse, piOfB_prime);

                // composed randomness r'_{i,j} and s'_{i,j}, composition of randomness used to create Bj and B'
                // Calculate reencyption randomness used to mix shadow mix into real mix.
                for (int i = 1; i <= ell; i++) {
                    // Compose randomness r for homomorphic encryption(g^-d and g^d)
                    BigInteger shadowR = randROfBj.get(i - 1); //Randomness used to make reencryption of shadow mix.
                    BigInteger realR = randROfB_prime.get(i - 1); //Randomness used to make reencryption of real mix.
                    BigInteger composedR = shadowR.negate().add(realR); //.mod(q); // -r1 + r2 TODO: Do we need to mod q ???
                    reencDataBjRandomnessR.add(composedR);

                    // Compose randomness s for vote encryption
                    BigInteger shadowS = randROfBj.get(i - 1); //Randomness used to make reencryption of shadow mix.
                    BigInteger realS = randROfB_prime.get(i - 1); //Randomness used to make reencryption of real mix.
                    BigInteger composedS = shadowS.negate().add(realS); //.mod(q); // -s1 + s2 TODO: Do we need to mod q ???
                    reencDataBjRandomnessS.add(composedS);
                }

            } else { // challenge c = 0
                // randomness  r_{i,j} and s_{i,j} used to create Bj
                reencDataBjRandomnessR = randROfBj;
                reencDataBjRandomnessS = randSOfBj;

                // permutation pi_j used to create Bj
                permDataBj = piOfBj; //piOfBj;
            }

            //Add reenc data
            mapOfReencDataBjRandomnessR.put(j, reencDataBjRandomnessR);
            mapOfReencDataBjRandomnessS.put(j, reencDataBjRandomnessS);

            //Add permutation data
            mapOfPermDataBj.put(j, permDataBj);
        }

        return new MixnetProof(Bcal_prime, mapOfBj, mapOfReencDataBjRandomnessR, mapOfReencDataBjRandomnessS, mapOfPermDataBj);
    }


    private Step2Statement step2(List<MixBallot> ballots) {

        int size = ballots.size();
        /*
        Instead of randomly permuting the elements of the new
        ballot set, the re-encrypted ballots can simply be sorted
        numerically, alphabetically, or lexicographically
        to obscure the association between the original encrypted ballots
        and the re-encrypted ballots
        */

        //New permutation
        List<Integer> permutation = UTIL.newPermutation(size, random);

        //Permute ballots
        List<MixBallot> permutedBallots = UTIL.permute(ballots, permutation);

        return new Step2Statement(permutation, permutedBallots);
    }


    private Step1Statement step1(List<MixBallot> listOfB, int ell) {
        List<MixBallot> listOfBi_prime = new ArrayList<>(ell);
        List<BigInteger> listOfRandR = new ArrayList<>();
        List<BigInteger> listOfRandS = new ArrayList<>();
        for (int i = 1; i <= ell; i++) {

            // bi = {c1=Enc_pk(1)=(g^r,1h^r),c2=Enc_pk(v)}
            MixBallot bi = listOfB.get(i - 1);

            BigInteger fromInclusive = BigInteger.valueOf(1);
            BigInteger toExclusive = BigInteger.valueOf(3);
            BigInteger ri = UTIL.getRandomElement(fromInclusive, toExclusive, this.random);
            BigInteger si = UTIL.getRandomElement(fromInclusive, toExclusive, this.random);
            BigInteger e = BigInteger.valueOf(1); // g^0 = 1, i.e. neutral element of the multiplicative homomomorphic encryption scheme ElGamal
            CipherText c1_reenc = elgamal.encrypt(e, pk, ri.longValueExact()); // c1 =  Enc_pk(e=1; ri)
            CipherText c2_reenc = elgamal.encrypt(e, pk, si.longValueExact()); // c2 =  Enc_pk(e=1; si)

            MixBallot bi_prime = bi.multiply(new MixBallot(c1_reenc, c2_reenc)); // bi^\prime = bi \cdot c

            listOfRandR.add(ri);
            listOfRandS.add(si);
            listOfBi_prime.add(bi_prime);
        }

        return new Step1Statement(listOfRandR, listOfRandS, listOfBi_prime);
    }

    private List<Boolean> hash(Map<Integer, List<MixBallot>> mapOfBj) {

        byte[] concatenated = new byte[]{};

        // \mathcal{B}_j for j in [1,n]
        for (List<MixBallot> Bcal_j : mapOfBj.values()) {
            for (MixBallot bj : Bcal_j) {
                concatenated = Bytes.concat(concatenated, bj.toByteArray());
            }
        }

        byte[] hashed = this.hashH.digest(concatenated);

        // create list of C
        List<Boolean> listOfC = ByteConverter.valueOf(hashed, hashed.length);

        // TODO: HACKY ONLY TAKES THE FIRST n......
        List<Boolean> firstNElementsOfC = listOfC.stream().limit(n).collect(Collectors.toList());

        assert firstNElementsOfC.size() == n : "listOfC.size()=" + listOfC.size() + " != n=" + n;
        return firstNElementsOfC;
    }




    public boolean verify(List<MixBallot> bcalList, MixnetProof proof) {

        Map<Integer, List<MixBallot>> mapOfBj = proof.getMapOfBj();

        List<Boolean> listOfCis = hash(mapOfBj);

        for (Map.Entry<Integer, List<MixBallot>> entry : mapOfBj.entrySet()) {
            Integer i = entry.getKey();

            // \matchal{B}_j
            List<MixBallot> bCal_j = entry.getValue();
            Boolean ci = listOfCis.get(i);
            if (ci) {
                /* *******************
                 * Step 6 (c_i == 1)
                 * Bi =?= B_prime
                 *********************/


                return false;
            } else {
                /* *******************
                 * Step 5 (c_i == 0)
                 * B =?= B_j
                 *********************/
                boolean compared = UTIL.CompareLists(bcalList, bCal_j);


                return compared;

            }

        }


        return true;
    }

}
