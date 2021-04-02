package project.mixnet;

import com.google.common.primitives.Bytes;
import project.HASH;
import project.UTIL;
import project.dao.mixnet.*;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;

public class Mixnet {
    private final ElGamal elgamal;
    private final Random random;
    private final ElGamalPK pk;
    private final BigInteger p;
    private final BigInteger q;

    public Mixnet(ElGamal elgamal, ElGamalPK pk, Random random) {
        this.elgamal = elgamal;
        this.random = random;
        this.pk = pk;
        this.p = this.pk.group.p;
        this.q = this.pk.group.q;
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
            BigInteger ri = UTIL.getRandomElement(BigInteger.ONE, q, random);
            BigInteger si = UTIL.getRandomElement(BigInteger.ONE, q, random);

            //Make reencryption ciphertets
            BigInteger e = ElGamal.getNeutralElement();
            Ciphertext reencryptRi = elgamal.encrypt(e, pk, ri);
            Ciphertext reencryptSi = elgamal.encrypt(e, pk, si);

            //Reencrypt
            Ciphertext m1 = ballot.getCombinedCredential().multiply(reencryptRi, p);
            Ciphertext m2 = ballot.getEncryptedVote().multiply(reencryptSi, p);


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

    public MixProof proveMix(MixStatement statement, MixSecret originalMixSecret, int kappa) {
        List<MixBallot> ballots = statement.ballots;
        List<MixBallot> mixedBallots = statement.mixedBallots;

        //Do shadow mix
        List<MixStruct> shadowMixStructs = new ArrayList<>();
        List<List<MixBallot>> shadowMixes = new ArrayList<>();
        for (int i = 0; i < kappa; i++) {
            MixStruct shadowMixStruct = mix(ballots);

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

/*
    private List<Boolean> hash(List<List<MixBallot>> ballots, int kappa) {
        byte[] concatenated = new byte[]{};

        // \mathcal{B}_j for j in [1,n]
        for (List<MixBallot> shadowMix : ballots) {
            for (MixBallot mixBallot : shadowMix) {
                concatenated = Bytes.concat(concatenated, mixBallot.toByteArray());
            }
        }

        byte[] hashed = HASH.hash(concatenated);

        // create list of C
        List<Boolean> listOfC = ByteConverter.valueOf(hashed, kappa);
        assert listOfC.size() == kappa : "listOfC.size()=" + listOfC.size() + " != kappa=" + kappa;

        return listOfC;
    }
    */

    public boolean verify(MixStatement statement, MixProof proof, int kappa) {
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

            BigInteger e = ElGamal.getNeutralElement();

            //c1 * Enc(1,R)
            Ciphertext reencryptionFactorR = this.elgamal.encrypt(e, pk, randomnessR.get(i));
            Ciphertext c1 = destinationBallot.getCombinedCredential().multiply(reencryptionFactorR, p);

            //c2 * Enc(1,S)
            Ciphertext reencryptionFactorS = this.elgamal.encrypt(e, pk, randomnessS.get(i));
            Ciphertext c2 = destinationBallot.getEncryptedVote().multiply(reencryptionFactorS, p);

            reencryptedSourceMix.add(new MixBallot(c1, c2));
        }

        //Apply permutation
        List<MixBallot> mixedSourceMix = UTIL.permute(reencryptedSourceMix, secret.permutation);

        //Verify
        return mixedSourceMix.equals(destinationMix);
    }

}
