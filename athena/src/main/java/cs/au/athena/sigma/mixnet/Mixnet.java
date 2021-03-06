package cs.au.athena.sigma.mixnet;

import cs.au.athena.HASH;
import cs.au.athena.UTIL;
import cs.au.athena.athena.bulletinboard.MixedBallotsAndProof;
import cs.au.athena.dao.mixnet.*;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.Group;
import cs.au.athena.elgamal.ElGamalPK;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class Mixnet {
    private final Random random;

    public Mixnet(Random random) {
        this.random = random;
    }

    public Mixnet() {
        this.random = new SecureRandom();
    }

    public MixedBallotsAndProof mixAndProveMix(List<MixBallot> ballots, ElGamalPK pk, int kappa) {
        long startTime = System.nanoTime();

        MixStruct mixStruct = mix(ballots, pk);

        long endTime = System.nanoTime();
        UTIL.printNarrowEvalMetrics(String.format("mix of %d took: ", ballots.size()), startTime, endTime);


        List<MixBallot> mixedBallots = mixStruct.mixedBallots;

        MixStatement statement = new MixStatement(ballots, mixedBallots);
        MixSecret secret = mixStruct.mixSecret;

        startTime = System.nanoTime();
        MixProof proof = proveMix(statement, secret, pk, kappa);
        endTime = System.nanoTime();
        UTIL.printNarrowEvalMetrics(String.format("proveMix of %d took: ", ballots.size()), startTime, endTime);


        return new MixedBallotsAndProof(mixedBallots, proof);
    }

    //Reencrypts and permutes the ballots. Returns the mixed ballots and secret(permutation and reencryption randomness).
    private MixStruct mix(List<MixBallot> ballots, ElGamalPK pk) {
        int ell = ballots.size();

        //Reencrypt each ballot
        List<BigInteger> randomnessR = new ArrayList<>();           //For private credential
        List<BigInteger> randomnessS = new ArrayList<>();           //For vote
        List<MixBallot> reencryptedBallots = new ArrayList<>();     //Result of cs.au.cs.au.athena.athena.mixnet

        for (int i = 0; i < ell; i++) {
            MixBallot ballot = ballots.get(i);

            //Make randomness
            BigInteger ri = UTIL.getRandomElement(BigInteger.ONE, pk.group.q, random);
            BigInteger si = UTIL.getRandomElement(BigInteger.ONE, pk.group.q, random);

            //Make reencryption ciphertets
            BigInteger e = ElGamal.getNeutralElement();
            Ciphertext reencryptRi = ElGamal.encrypt(e, pk, ri);
            Ciphertext reencryptSi = ElGamal.encrypt(e, pk, si);

            //Reencrypt
            Ciphertext m1 = ballot.getCombinedCredential().multiply(reencryptRi, pk.group);
            Ciphertext m2 = ballot.getEncryptedVote().multiply(reencryptSi, pk.group);


            // M(combined, vote)
            MixBallot reencryptedBallot = new MixBallot(m1, m2);

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

    private MixProof proveMix(MixStatement statement, MixSecret originalMixSecret, ElGamalPK pk, int kappa) {
        List<MixBallot> ballots = statement.ballots;

        //Do shadow mix
        List<MixStruct> shadowMixStructs = new ArrayList<>();
        List<List<MixBallot>> shadowMixes = new ArrayList<>();
        for (int i = 0; i < kappa; i++) {
            MixStruct shadowMixStruct = mix(ballots, pk);

            shadowMixStructs.add(shadowMixStruct);
            shadowMixes.add(shadowMixStruct.mixedBallots);
        }

        //Calculate challenges from hash
        List<Boolean> challenges = HASH.computeChallenges(kappa, shadowMixes);

        //Calculate proof values
        List<MixSecret> composedMixSecrets = new ArrayList<>();
        for (int j = 0; j < kappa; j++) {
            //Extract challenge
            Boolean challenge = challenges.get(j);

            //Extract shadow mix secret
            MixSecret shadowMixSecret = shadowMixStructs.get(j).mixSecret;

            //Use originalMixSecret and shadowMixSecret, to answer challenge
            MixSecret composedMixSecret = answerChallenge(challenge, originalMixSecret, shadowMixSecret, pk.group);

            composedMixSecrets.add(composedMixSecret);
        }

        return new MixProof(shadowMixes, composedMixSecrets);
    }

    private MixSecret answerChallenge(Boolean challenge, MixSecret originalMixSecret, MixSecret shadowMixSecret, Group group) {
        int ell = originalMixSecret.permutation.size();

        if (challenge) {// challenge c = 1
            //Calculate composed reencyption randomness for each ballot
            List<BigInteger> composedRandomnessR = new ArrayList<>();
            List<BigInteger> composedRandomnessS = new ArrayList<>();
            for (int i = 0; i < ell; i++) {
                // Compose randomness r for encrypted private credential
                BigInteger shadowR = shadowMixSecret.randomnessR.get(i);    //Randomness used to make reencryption of shadow mix.
                BigInteger realR = originalMixSecret.randomnessR.get(i);    //Randomness used to make reencryption of real mix.
                BigInteger composedR = shadowR.negate().add(realR).mod(group.q);  // -r1 + r2
                composedRandomnessR.add(composedR);

                // Compose randomness s for encrypted vote
                BigInteger shadowS = shadowMixSecret.randomnessS.get(i);    //Randomness used to make reencryption of shadow mix.
                BigInteger realS = originalMixSecret.randomnessS.get(i);    //Randomness used to make reencryption of real mix.
                BigInteger composedS = shadowS.negate().add(realS).mod(group.q);  // -s1 + s2
                composedRandomnessS.add(composedS);
            }

            // Calculate composed permutation
            List<Integer> shadowPermutationInverse = UTIL.inversePermutation(shadowMixSecret.permutation);
            List<Integer> composedPermutation = UTIL.composePermutation(shadowPermutationInverse, originalMixSecret.permutation);

            //Apply shadowPermutation to randomness
            composedRandomnessR = UTIL.permute(composedRandomnessR, shadowMixSecret.permutation);
            composedRandomnessS = UTIL.permute(composedRandomnessS, shadowMixSecret.permutation);

            return new MixSecret(composedPermutation, composedRandomnessR, composedRandomnessS);
        } else { // challenge c = 0
            return shadowMixSecret; //permutation, randomnessR, randomnessS
        }
    }


    public static boolean verify(MixStatement statement, MixProof proof, ElGamalPK pk, int kappa) {
        // Check proof size
        if(proof.shadowMixes.size() != kappa) {
            return false;
        }

        List<MixBallot> originalBallots = statement.ballots;
        List<MixBallot> mixedOriginalBallots = statement.mixedBallots;
        List<List<MixBallot>> shadowMixes = proof.shadowMixes;

        // in this list there is n elements....
        List<Boolean> challenges = HASH.computeChallenges(kappa, shadowMixes);
        for (int j = 0; j < kappa; j++) {
            //For each shadow mix
            List<MixBallot> shadowMix = proof.shadowMixes.get(j);
            MixSecret mixSecret = proof.shadowSecrets.get(j);

            //Check each challenge
            Boolean challenge = challenges.get(j);
            List<MixBallot> sourceMix, destinationMix;

            //Change proof based on challenge
            if (challenge) { // c = 1
                // source = B_j
                // dest = B^prime
                // source \equiv dest
                sourceMix = shadowMix;
                destinationMix = mixedOriginalBallots;
            } else {
                // source = B
                // dest = B_j
                // source \equiv dest
                sourceMix = originalBallots;
                destinationMix = shadowMix;
            }

            if (!verifyShadowMix(sourceMix, destinationMix, mixSecret, pk)) {
                return false;
            }
        }

        return true;
    }

    private static boolean verifyShadowMix(List<MixBallot> sourceMix, List<MixBallot> destinationMix, MixSecret secret, ElGamalPK pk) {
        int ell = sourceMix.size();
        List<BigInteger> randomnessR = secret.randomnessR;
        List<BigInteger> randomnessS = secret.randomnessS;

        //Undo permutation
        // c = 0 => permutes B
        // c = 1 => permutes mixed
        //List<MixBallot> destinationMix = UTIL.permute(destinationMix, permutation);

        List<MixBallot> reencryptedSourceMix = new ArrayList<>(ell);
        for (int i = 0; i < ell; i++) {
            MixBallot sourceBallot = sourceMix.get(i);

            BigInteger e = ElGamal.getNeutralElement();

            //c1 * Enc(1,R)
            Ciphertext reencryptionFactorR = ElGamal.encrypt(e, pk, randomnessR.get(i));
            Ciphertext c1 = sourceBallot.getCombinedCredential().multiply(reencryptionFactorR, pk.group);

            //c2 * Enc(1,S)
            Ciphertext reencryptionFactorS = ElGamal.encrypt(e, pk, randomnessS.get(i));
            Ciphertext c2 = sourceBallot.getEncryptedVote().multiply(reencryptionFactorS, pk.group);

            reencryptedSourceMix.add(new MixBallot(c1, c2));
        }

        //Apply permutation
        List<MixBallot> mixedSourceMix = UTIL.permute(reencryptedSourceMix, secret.permutation);

        //Verify
        return mixedSourceMix.equals(destinationMix);
    }

}
