package project.mixnet;

import com.google.common.primitives.Bytes;
import jdk.jshell.execution.Util;
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
    private final int n = 256;
    private final MessageDigest hashH;
    private final ElGamal elgamal;
    private final Random random;
    private final ElGamalPK pk;
    private final BigInteger p;
    private final BigInteger q;

    public Mixnet(Factory factory) {
        this.hashH = factory.getHash();
        this.elgamal = factory.getElgamal();
        this.random = factory.getRandom();
        this.pk = factory.getPK();
        this.p = this.pk.getGroup().getP();
        this.q = this.pk.getGroup().getQ();
    }

    //Reencrypts and permutes the ballots. Returns the mixed ballots and secret(permutation and reencryption randomness).
    public MixStruct mix(List<MixBallot> ballots) {
        int ell = ballots.size();

        //Reencrypt each ballot
        List<BigInteger> randomnessR = new ArrayList<>();           //For private credential
        List<BigInteger> randomnessS = new ArrayList<>();           //For vote
        List<MixBallot> reencryptedBallots = new ArrayList<>();     //Result of mixnet

        for (int i = 0; i < ell; i++) {
            MixBallot ballot = ballots.get(i);

            //Make randomness
            BigInteger toExclisive = BigInteger.valueOf(256); //TODO: q?
            BigInteger ri = UTIL.getRandomElement(toExclisive, random);
            BigInteger si = UTIL.getRandomElement(toExclisive, random);

            //Make reencryption ciphertets
            CipherText reencryptRi = elgamal.encrypt(BigInteger.ONE, pk, ri);
            CipherText reencryptSi = elgamal.encrypt(BigInteger.ONE, pk, si);

            //Reencrypt
            CipherText c1 = ballot.getC1().multiply(reencryptRi, p);
            CipherText c2 = ballot.getC2().multiply(reencryptSi, p);
            MixBallot reencryptedBallot = new MixBallot(c1, c2);

            //Store randomness
            randomnessR.add(ri);
            randomnessS.add(si);

            //Store reencryptions
            reencryptedBallots.add(reencryptedBallot);
        }

        //Permute ballots
        List<Integer> permutation = UTIL.newPermutation(ell, random);
        List<MixBallot> mixedBallots = UTIL.permute(reencryptedBallots, permutation);

        //Return
        MixSecret secret = new MixSecret(permutation, randomnessR, randomnessS);
        return new MixStruct(mixedBallots, secret);
    }

    public MixProof proveMix(MixStatement statement, MixSecret originalMixSecret) {
        List<MixBallot> ballots = statement.ballots;
        List<MixBallot> mixedBallots = statement.mixedBallots;

        //Do shadow mix
        List<MixStruct> shadowMixStructs = new ArrayList<>();
        List<List<MixBallot>> shadowMixes = new ArrayList<>(n);
        for (int i = 0; i < n; i++) { // Improve?
            MixStruct shadowMixStruct = mix(ballots); // step 1 + 2

            shadowMixStructs.add(shadowMixStruct);
            shadowMixes.add(shadowMixStruct.mixedBallots);
        }

        //Calculate challenges from hash
        List<Boolean> challenges = hash(shadowMixes);

        //Calculate proof values
        List<MixSecret> composedMixSecrets = new ArrayList<>(n);
        for (int j = 0; j < n; j++) {
            //Extract challenge
            Boolean challenge = challenges.get(j);

            //Extract shadow mix secret
            MixSecret shadowMixSecret = shadowMixStructs.get(j).secret;

            //Use originalMixSecret and shadowMixSecret, to answer challenge
            MixSecret composedMixSecret = answerChallenge(challenge, originalMixSecret, shadowMixSecret);

            composedMixSecrets.add(composedMixSecret);
        }

        return new MixProof(shadowMixes, composedMixSecrets);
    }

    private MixSecret answerChallenge(Boolean challenge, MixSecret originalMixSecret, MixSecret shadowMixSecret) {
        int ell = originalMixSecret.permutation.size();

        if (challenge) {// challenge c = 1
            // Calculate composed permutation
            List<Integer> shadowPermutationInverse = UTIL.inversePermutation(shadowMixSecret.permutation);
            List<Integer> composedPermutation = UTIL.composePermutation(shadowPermutationInverse, originalMixSecret.permutation);

            //Calculate composed reencyption randomness for each ballot
            List<BigInteger> composedRandomnessR = new ArrayList<>();
            List<BigInteger> composedRandomnessS = new ArrayList<>();
            for (int i = 0; i < ell; i++) {
                // TODO: Permute. IMPORTATNT!
                // Compose randomness r for encrypted private credential
                BigInteger shadowR = shadowMixSecret.randomnessR.get(i);    //Randomness used to make reencryption of shadow mix.
                BigInteger realR = originalMixSecret.randomnessR.get(i);    //Randomness used to make reencryption of real mix.
                BigInteger composedR = shadowR.negate().add(realR).mod(q);  // -r1 + r2
                composedRandomnessR.add(composedR);

                // Compose randomness s for encrypted vote
                BigInteger shadowS = shadowMixSecret.randomnessS.get(i);    //Randomness used to make reencryption of shadow mix.
                BigInteger realS = originalMixSecret.randomnessS.get(i);    //Randomness used to make reencryption of real mix.
                BigInteger composedS = shadowS.negate().add(realS).mod(q);  // -s1 + s2
                composedRandomnessS.add(composedS);
            }
            return new MixSecret(composedPermutation, composedRandomnessR, composedRandomnessS);

        } else { // challenge c = 0
            return shadowMixSecret;
        }
    }


    private List<Boolean> hash(List<List<MixBallot>> ballots) {
        byte[] concatenated = new byte[]{};

        // \mathcal{B}_j for j in [1,n]
        for (List<MixBallot> shadowMix : ballots) {
            for (MixBallot mixBallot : shadowMix) {
                concatenated = Bytes.concat(concatenated, mixBallot.toByteArray());
            }
        }

        byte[] hashed = this.hashH.digest(concatenated);

        // create list of C
        List<Boolean> listOfC = ByteConverter.valueOf(hashed, n);
        assert listOfC.size() == n : "listOfC.size()=" + listOfC.size() + " != n= " + n;

        return listOfC;

    }

    public boolean verify(MixStatement statement, MixProof proof) {
        int ell = statement.ballots.size();
        System.out.println("Verify\n\n\n\n\n\n\n\n\n\n\n\n");

        // B^\prime (step 2)
        List<MixBallot> originalBallots = statement.ballots;
        List<MixBallot> mixedOriginalBallots = statement.mixedBallots;
        List<List<MixBallot>> shadowMixes = proof.shadowMixes;

        // in this list there is n elements....
        List<Boolean> challenges = hash(shadowMixes); //TODO: Er det nok? Skal vi have MixStatement med? :O

        for (int j = 0; j < n; j++) {
            //For each shadow mix
            //Get permutation
            //Get R
            //Get S
            List<MixBallot> shadowMix = proof.shadowMixes.get(j);
            List<Integer> permutation = proof.shadowSecrets.get(j).permutation;
            List<BigInteger> randomnessR = proof.shadowSecrets.get(j).randomnessR;
            List<BigInteger> randomnessS = proof.shadowSecrets.get(j).randomnessS;


            //Check each challenge
            Boolean challenge = challenges.get(j);
            if (challenge) { // c = 1


            } else {

                for (int i = 0; i < ell; i++) {
                    MixBallot ballot = originalBallots.get(i); //Mixed original ballot
                    MixBallot shadowBallot = shadowMix.get(i);

                    //TODO: Permute: permutation

                    //c1 * Enc(1,R)
                    CipherText reencryptionFactorR = this.elgamal.encrypt(BigInteger.ONE, pk, randomnessR.get(i));
                    CipherText c1 = ballot.getC1().multiply(reencryptionFactorR, p);


                    //c2 * Enc(1,S)
                    CipherText reencryptionFactorS = this.elgamal.encrypt(BigInteger.ONE, pk, randomnessS.get(i));
                    CipherText c2 = ballot.getC2().multiply(reencryptionFactorS, p);

                    //Verify
                    boolean isValid = c1.equals(shadowBallot.getC1()) && c2.equals(shadowBallot.getC2());
                    if (!isValid) {
//                      System.out.println("originalBallots = " + originalBallots.toString() + ", \nproof = " + proof);
                        return false;
                    }
                }

                //return compared;
            }
        }

        return true;
    }

}


