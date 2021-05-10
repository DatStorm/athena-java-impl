package cs.au.athena.athena.distributed;

import cs.au.athena.GENERATOR;
import cs.au.athena.athena.AthenaCommon;
import cs.au.athena.SecretSharingUTIL;
import cs.au.athena.dao.bulletinboard.CombinedCiphertextAndProof;
import cs.au.athena.dao.bulletinboard.CommitmentAndProof;
import cs.au.athena.dao.bulletinboard.DecryptionShareAndProof;
import cs.au.athena.dao.mixnet.MixProof;
import cs.au.athena.dao.mixnet.MixStatement;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma3;
import cs.au.athena.sigma.Sigma4;
import cs.au.athena.sigma.mixnet.Mixnet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class SigmaCommonDistributed {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("SigmaCommonDistributed: ");



    public static boolean verifyPK(List<CommitmentAndProof> commitmentAndProofs, Group group, int kappa) {
        Sigma1 sigma1 = new Sigma1();


        // Verify for every coefficient
        for (CommitmentAndProof comProof : commitmentAndProofs) {
            BigInteger commitment = comProof.commitment;
            Sigma1Proof rho = comProof.proof;

            boolean isValid = sigma1.VerifyKey(commitment, rho, group, kappa);

            if (!isValid){
                return false;
            }
        }

        return true;
    }





    public static List<CombinedCiphertextAndProof> computeHomoCombinationAndProofs(List<Ciphertext> ciphertexts, BigInteger nonce, ElGamalSK sk, int kappa) {
        int ell = ciphertexts.size();
        Sigma4 sigma4 = new Sigma4();

        List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof = new ArrayList<>(ell);

        Ciphertext previousCiphertext = null;
        Ciphertext previousCombinedCiphertext = null;

        // Nonce each ciphertext, and compute proof
        for (int i = 0; i < ell; i++) {
            Ciphertext ciphertext = ciphertexts.get(i);

            // Homomorpically re-encrypt(by raising to power n) ballot and decrypt
            Ciphertext combinedCiphertext = AthenaCommon.homoCombination(ciphertext, nonce, sk.pk.group);

            // Prove that the same nonce was used for all ballots.
            if (listOfCombinedCiphertextAndProof.size() > 0) {
                //Prove c_{i−1} and c_{i} are derived by iterative homomorphic combination wrt nonce n
                List<Ciphertext> listCiphertexts = Arrays.asList(previousCiphertext, ciphertext);
                List<Ciphertext> listCombined = Arrays.asList(previousCombinedCiphertext, combinedCiphertext);

                Sigma4Proof proof = sigma4.proveCombination(sk, listCombined, listCiphertexts, nonce, kappa);
//                assert sigma4.verifyCombination(sk.pk, listCombined, listCiphertexts, proof, kappa); // TODO: comment this OUT!

                listOfCombinedCiphertextAndProof.add(new CombinedCiphertextAndProof(combinedCiphertext, proof));
            } else {
                listOfCombinedCiphertextAndProof.add(new CombinedCiphertextAndProof(combinedCiphertext, null));
            }

            previousCiphertext = ciphertext;
            previousCombinedCiphertext = combinedCiphertext;
        }

        return listOfCombinedCiphertextAndProof;
    }


    public static boolean verifyHomoCombPfr(List<Ciphertext> ciphertexts, List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof, ElGamalPK pk, int kappa) {
        int ell = ciphertexts.size();
        Sigma4 sigma4 = new Sigma4();

        // First iteration
        Ciphertext previousCiphertext = ciphertexts.get(0);
        CombinedCiphertextAndProof previousObj = listOfCombinedCiphertextAndProof.get(0);

        for (int i = 1; i < ell; i++) {
            Ciphertext ciphertext = ciphertexts.get(i);
            CombinedCiphertextAndProof obj = listOfCombinedCiphertextAndProof.get(i);

            // Make proof statement
            List<Ciphertext> listCiphertexts = Arrays.asList(previousCiphertext, ciphertext);
            List<Ciphertext> listCombined = Arrays.asList(previousObj.combinedCiphertext, obj.combinedCiphertext);
            Sigma4Proof proof = obj.proof;

            // Verify proof
            boolean isValid = sigma4.verifyCombination(pk, listCombined, listCiphertexts, proof, kappa);
            //logger.info(MARKER, String.format("i=%d = %b: Verifying: %s", i, isValid, obj));

            if(!isValid) {
                return false;
            }

            previousCiphertext = ciphertext;
            previousObj = obj;
        }

        return true;
    }

    public static List<CombinedCiphertextAndProof> proveHomoCombPfd(List<Ciphertext> ciphertexts, Random random, ElGamalSK sk, int kappa) {
        int ell = ciphertexts.size();
        Sigma4 sigma4 = new Sigma4();

        // Nonce each ciphertext, and compute proof
        List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof = new ArrayList<>(ell);
        for (Ciphertext ciphertext : ciphertexts) {
            BigInteger nonce = GENERATOR.generateUniqueNonce(BigInteger.ONE, sk.pk.group.q, random);

            // Homomorpically re-encrypt(by raising to power n) ballot and decrypt
            Ciphertext combinedCiphertext = AthenaCommon.homoCombination(ciphertext, nonce, sk.pk.group);

            //Prove the combination of a valid combination nonce n
            Sigma4Proof omega = sigma4.proveCombination(sk, combinedCiphertext, ciphertext, nonce, kappa);
            listOfCombinedCiphertextAndProof.add(new CombinedCiphertextAndProof(combinedCiphertext, omega));
        }

        return listOfCombinedCiphertextAndProof;
    }

    public static boolean verifyHomoCombPfd(List<Ciphertext> ciphertexts, List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof, ElGamalPK pk, int kappa) {
        int ell = ciphertexts.size();
        Sigma4 sigma4 = new Sigma4();

        for (int i = 0; i < ell; i++) {
            Ciphertext ciphertext = ciphertexts.get(i);
            CombinedCiphertextAndProof obj = listOfCombinedCiphertextAndProof.get(i);

            // Make proof statement
            List<Ciphertext> listCiphertexts = Collections.singletonList(ciphertext);
            List<Ciphertext> listCombined = Collections.singletonList(obj.combinedCiphertext);
            Sigma4Proof proof = obj.proof;

            // Verify proof
            boolean isValid = sigma4.verifyCombination(pk, listCombined, listCiphertexts, proof, kappa);

            if(!isValid) {
//                logger.info(MARKER, String.format("-----> Sigma4 verification failed for: %s", ciphertext.toOneLineShortString()));
                return false;
            }
        }

        return true;
    }


    /**
     * decryption share d_i = c_1^{sk_i} where ciphertext c=(c1,c2)
     * and sk_i is the share of the secret key held by tallier T_i
     */
    public static List<DecryptionShareAndProof> computeDecryptionShareAndProofs(List<Ciphertext> ciphertexts, ElGamalSK sk, int kappa) {
        Sigma3 sigma3 = new Sigma3();
        List<DecryptionShareAndProof> decryptionSharesAndProofs = new ArrayList<>(ciphertexts.size());

        // generate decryption shares and proofs for all ballots
        for (Ciphertext ciphertext : ciphertexts) {
            // Compute decryption share and proof
            BigInteger decryptionShare = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk);

            // Prove decryption share, i.e. show knowledge of P(j) s.t. h_j = g^{P(j)}
            Sigma3Proof proof = sigma3.proveDecryptionShare(ciphertext, decryptionShare, sk, kappa);

            // Add to list
            decryptionSharesAndProofs.add(new DecryptionShareAndProof(decryptionShare, proof));
        }

//        assert verifyDecryptionShareAndProofs(ciphertexts, decryptionSharesAndProofs, sk.pk, kappa): "computeDecryptionShareAndProofs result is invalid";

        return decryptionSharesAndProofs;
    }

    public static boolean verifyDecryptionShareAndProofs(List<Ciphertext> ciphertexts, List<DecryptionShareAndProof> decryptionShareAndProofs, ElGamalPK pk, int kappa) {
        int ell = ciphertexts.size();
        Sigma3 sigma3 = new Sigma3();

        // Verify each entry
        for (int i = 0; i < ell; i++) {
            // Make proof statement
            Ciphertext ciphertext = ciphertexts.get(i);
            DecryptionShareAndProof decryptionShareAndProof = decryptionShareAndProofs.get(i);

            //Verify proof
            boolean isValid = sigma3.verifyDecryptionShare(ciphertext, decryptionShareAndProof.share, decryptionShareAndProof.proof, pk, kappa);

            if (!isValid){
                return false;
            }
        }

        return true;
    }

    public static boolean verifyMix(MixStatement statement, MixProof mixProof, ElGamalPK pk, int kappa) {
        return Mixnet.verify(statement, mixProof, pk, kappa);
    }
}
