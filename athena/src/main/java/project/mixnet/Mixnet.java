package project.mixnet;

import com.google.common.primitives.Bytes;
import project.CONSTANTS;
import project.UTIL;
import project.dao.mixnet.*;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;

public class Mixnet {
    private final int n = CONSTANTS.MIXNET_N;
    private final MessageDigest hashH;
    private final ElGamal elgamal;
    private final Random random;
    private final ElGamalPK pk;
    private final BigInteger p;
    private final BigInteger q;

    public Mixnet(MessageDigest hashH, Random random, ElGamal elgamal, ElGamalPK pk ) {
        this.hashH = hashH;
        this.elgamal = elgamal;
        this.random = random;
        this.pk = pk;
        this.p = this.pk.getGroup().getP();
        this.q = this.pk.getGroup().getQ();
    }

    public Mixnet(MessageDigest hash, Random random) {
        this.hashH = hash;
        this.random = random;

        System.out.println("Mixnet.Mixnet constructor:: Elgamal missing....");
        this.elgamal = null;
        this.pk = null;
        this.p = null;
        this.q = null;
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
            BigInteger ri = UTIL.getRandomElement(BigInteger.ZERO, q, random);
            BigInteger si = UTIL.getRandomElement(BigInteger.ZERO, q, random);

            //Make reencryption ciphertets
            Ciphertext reencryptRi = elgamal.encrypt(BigInteger.ONE, pk, ri);
            Ciphertext reencryptSi = elgamal.encrypt(BigInteger.ONE, pk, si);

            //Reencrypt
            Ciphertext c1 = ballot.getC1().multiply(reencryptRi, p);
            Ciphertext c2 = ballot.getC2().multiply(reencryptSi, p);
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
        List<List<MixBallot>> shadowMixes = new ArrayList<>();
        for (int i = 0; i < n; i++) { // Improve?
            MixStruct shadowMixStruct = mix(ballots);

            shadowMixStructs.add(shadowMixStruct);
            shadowMixes.add(shadowMixStruct.mixedBallots);
        }

        //Calculate challenges from hash
        List<Boolean> challenges = hash(shadowMixes);

        //Calculate proof values
        List<MixSecret> composedMixSecrets = new ArrayList<>();
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
            //Calculate composed reencyption randomness for each ballot
            List<BigInteger> composedRandomnessR = new ArrayList<>();
            List<BigInteger> composedRandomnessS = new ArrayList<>();
            for (int i = 0; i < ell; i++) {
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
        assert listOfC.size() == n : "listOfC.size()=" + listOfC.size() + " != n=" + n;

        return listOfC;
    }

    public boolean verify(MixStatement statement, MixProof proof) {

        // B^\prime (step 2)
        List<MixBallot> originalBallots = statement.ballots;
        List<MixBallot> mixedOriginalBallots = statement.mixedBallots;
        List<List<MixBallot>> shadowMixes = proof.shadowMixes;

        // in this list there is n elements....
        List<Boolean> challenges = hash(shadowMixes);

        for (int j = 0; j < n; j++) {
            //For each shadow mix
            List<MixBallot> shadowMix = proof.shadowMixes.get(j);
            MixSecret mixSecret = proof.shadowSecrets.get(j);

            //Check each challenge
            Boolean challenge = challenges.get(j);
            List<MixBallot> sourceMix, destinationMix;

            //Change proof based on challenge
            if (challenge) { // c = 1
                sourceMix = shadowMix;
                destinationMix = mixedOriginalBallots;
            } else {
                sourceMix = shadowMix;
                destinationMix = originalBallots;
            }

            if (verifyShadowMix(sourceMix, destinationMix, mixSecret)) {
                return false;
            }
            
        }

        return true;
    }

    private boolean verifyShadowMix(List<MixBallot> sourceMix, List<MixBallot> destinationMix, MixSecret secret) {
        int ell = sourceMix.size();

        List<Integer> permutation = secret.permutation;
        List<BigInteger> randomnessR = secret.randomnessR;
        List<BigInteger> randomnessS = secret.randomnessS;

        //Undo permutation
        // c = 0 => permutes B
        // c = 1 => permutes mixed
        //List<MixBallot> destinationMix = UTIL.permute(destinationMix, permutation);

        List<MixBallot> reencryptedSourceMix = new ArrayList<>();
        for (int i = 0; i < ell; i++) {
            MixBallot sourceBallot = sourceMix.get(i); //Mixed original ballot
            MixBallot destinationBallot = destinationMix.get(i);

            //c1 * Enc(1,R)
            Ciphertext reencryptionFactorR = this.elgamal.encrypt(BigInteger.ONE, pk, randomnessR.get(i));
            Ciphertext c1 = destinationBallot.getC1().multiply(reencryptionFactorR, p);

            //c2 * Enc(1,S)
            Ciphertext reencryptionFactorS = this.elgamal.encrypt(BigInteger.ONE, pk, randomnessS.get(i));
            Ciphertext c2 = destinationBallot.getC2().multiply(reencryptionFactorS, p);

            reencryptedSourceMix.add(new MixBallot(c1, c2));
        }

        //Apply permutation
        List<MixBallot> mixedSourceMix = UTIL.permute(reencryptedSourceMix, secret.permutation);

        //Verify
        return mixedSourceMix.equals(destinationMix);
    }

}
