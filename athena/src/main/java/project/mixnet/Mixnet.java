package project.mixnet;

import com.google.common.collect.Lists;
import com.google.common.primitives.Bytes;
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
    private final int n = 32;
    private final MessageDigest hashH;
    private final ElGamal elgamal;
    private final Random random;
    private final ElGamalPK pk;
    private final BigInteger q;


    public Mixnet(Factory factory) {
        this.hashH = factory.getHash();
        this.elgamal = factory.getElgamal();
        this.random = factory.getRandom();
        this.pk = factory.getPK();
        this.q = this.pk.getGroup().getQ();

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
        List<MixBallot> B_prime = step2Stmnt.getPermutedBallots();


        /* *******************
         * Step 3
         *********************/
        Map<Integer, List<MixBallot>> mapOfBj = new HashMap<>(n);
        List<Step1Statement> listOfStep1StmtBj = new ArrayList<>(n);
        List<Step2Statement> listOfStep2StmtBj = new ArrayList<>(n);
        for (int j = 0; j < n; j++) {
            Step1Statement step1_j_stmnt = step1(listOfB, ell);
            listOfStep1StmtBj.add(step1_j_stmnt);

            List<MixBallot> listOfReencMixBallots = step1_j_stmnt.getListOfBi_prime();
            Step2Statement step2_j_stmnt = step2(listOfReencMixBallots);
            listOfStep2StmtBj.add(step2_j_stmnt);

            List<MixBallot> listOfPermutedMixBallots = step2_j_stmnt.getPermutedBallots();
            mapOfBj.put(j, listOfPermutedMixBallots);
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

        for (int j = 0; j < n; j++) {
            Boolean challengej = listOfCs.get(j);
            // Get reenc and perm data used to create B'
            List<BigInteger> randROfBj = listOfStep1StmtBj.get(j).getListOfRandR();
            List<BigInteger> randSOfBj = listOfStep1StmtBj.get(j).getListOfRandS();
            List<Integer> piOfBj = listOfStep2StmtBj.get(j).getPermutation();

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
                for (int i = 0; i < ell; i++) {
                    // Compose randomness r for homomorphic encryption(g^-d and g^d)
                    BigInteger shadowR = randROfBj.get(i); //Randomness used to make reencryption of shadow mix.
                    BigInteger realR = randROfB_prime.get(i); //Randomness used to make reencryption of real mix.
                    BigInteger composedR = shadowR.negate().add(realR).mod(q); // -r1 + r2
                    reencDataBjRandomnessR.add(composedR);

                    // Compose randomness s for vote encryption
                    BigInteger shadowS = randSOfBj.get(i); //Randomness used to make reencryption of shadow mix.
                    BigInteger realS = randSOfB_prime.get(i); //Randomness used to make reencryption of real mix.
                    BigInteger composedS = shadowS.negate().add(realS).mod(q); // -s1 + s2
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

        return new MixnetProof(B_prime, mapOfBj, mapOfReencDataBjRandomnessR, mapOfReencDataBjRandomnessS, mapOfPermDataBj);
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
            BigInteger toExclusive = BigInteger.valueOf(3); //FIXME: Need to be in Z_q!!!
            BigInteger ri = UTIL.getRandomElement(fromInclusive, toExclusive, this.random);
            BigInteger si = UTIL.getRandomElement(fromInclusive, toExclusive, this.random);
            BigInteger e = BigInteger.valueOf(1); // g^0 = 1, i.e. neutral element of the multiplicative homomorphic encryption scheme ElGamal
            CipherText c1_reenc = elgamal.encrypt(e, pk, ri.longValueExact()); // c1 =  Enc_pk(e=1; ri)
            CipherText c2_reenc = elgamal.encrypt(e, pk, si.longValueExact()); // c2 =  Enc_pk(e=1; si)

            MixBallot bi_prime = bi.multiply(new MixBallot(c1_reenc, c2_reenc), q); // bi^\prime = bi \cdot c

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
        assert hashed.length == n : "length not equal! hashed.length=";

        // create list of C
//        List<Boolean> listOfC = ByteConverter.valueOf(hashed, hashed.length);

        // TODO: HACKY ONLY TAKES THE FIRST n......
        //List<Boolean> firstNElementsOfC = listOfC.stream().limit(n).collect(Collectors.toList());

//        assert firstNElementsOfC.size() == n : "listOfC.size()=" + listOfC.size() + " != n=" + n;
//        return listOfC;
        List<Boolean> listOfC = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            listOfC.add(false);
        }
        return listOfC;
    }


    //Mixed, secret = Mix(preMix)

    //proof <= Prove(stament, secret)

    //Verify(statement, proof);

    //Statement : {preMixed, mixed}


    public boolean verify(List<MixBallot> originalBallots, MixnetProof proof) {
        int ell = originalBallots.size();
        BigInteger q = this.pk.getGroup().getQ();


        // B^\prime (step 2)
        List<MixBallot> mixedOriginalBallots = proof.getListOfB_prime();

        Map<Integer, List<MixBallot>> mapOfBj = proof.getMapOfBj();

        // in this list there is n elements....
        List<Boolean> challenges = hash(mapOfBj);

        for (Map.Entry<Integer, List<MixBallot>> entry : mapOfBj.entrySet()) {
            //Fore each shadow mix
            // \matchal{B}_j -- shadow mixed entry....
            List<MixBallot> Bj = entry.getValue();
            Integer j = entry.getKey();

            //Get permutation
            List<Integer> permutation = proof.getMapOfPermutationDataBj().get(j);
            //Get R
            List<BigInteger> reencR = proof.getMapOfReencDataBjRandomnessR().get(j);
            //Get S
            List<BigInteger> reencS = proof.getMapOfReencDataBjRandomnessS().get(j);


            // challanges c1...cn => index 0 = c1
            Boolean challenge_j = challenges.get(j);
            if (challenge_j) {
                /* *******************
                 * Step 6 (c_i == 1)
                 * Bi =?= B_prime
                 *********************/
                // Bj


            } else {
                /* *******************
                 * Step 5 (c_i == 0)
                 * B =?= B_j
                 *********************/
                // Shadow Mix: Bj
                // Real mix: originalBallots B
                // permutation: permutation
                // randomness: reencR, reencS
                // Check permutation and reencryption

                for (int i = 0; i < ell; i++) {
                    MixBallot originalBallot = originalBallots.get(i);
                    //MixBallot mixedBallot = mixedOriginalBallots.get(i); // B^\prime
                    MixBallot mixedShadowBallot = Bj.get(i); // FIXME: <---
                    //for each ballot:

                    //TODO: Permute

                    //c1 * Enc(1,R)
                    CipherText reencryptionFactorR = this.elgamal.encrypt(BigInteger.ONE, pk, reencR.get(i).longValueExact());
                    CipherText c1 = mixedShadowBallot.getC1().multiply(reencryptionFactorR, q);

                    //c2 * Enc(1,S)
                    CipherText reencryptionFactorS = this.elgamal.encrypt(BigInteger.ONE, pk, reencS.get(i).longValueExact());
                    CipherText c2 = mixedShadowBallot.getC2().multiply(reencryptionFactorS, q);

                    //Verify!!!!!!

//                    System.out.println(i + ": " + mixedShadowBallot);

                    boolean isValid = c1.compareTo(originalBallot.getC1()) && c2.compareTo(originalBallot.getC2());
                    if (!isValid) {
//                        System.out.println("originalBallots = " + originalBallots.toString() + ", \nproof = " + proof);
                        return false;
                    }
                }


                //return compared;

            }
        }

        return true;
    }

}
