package cs.au.athena.athena.distributed;

import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.bulletinboard.CombinedCiphertextAndProof;
import cs.au.athena.dao.bulletinboard.CommitmentAndProof;
import cs.au.athena.dao.bulletinboard.DecryptionShareAndProof;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma3;
import cs.au.athena.sigma.Sigma4;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class SigmaCommonDistributed {

    public static boolean verifyHomoComb(List<Ballot> ballots, List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof, ElGamalPK pk, int kappa) {
        int ell = ballots.size();
        Sigma4 sigma4 = new Sigma4();

        // First iteration
        CombinedCiphertextAndProof previousObj = listOfCombinedCiphertextAndProof.get(0);
        Ballot previousBallot = ballots.get(0);

        for (int i = 1; i < ell; i++) {
            CombinedCiphertextAndProof currentObj = listOfCombinedCiphertextAndProof.get(i);
            Ballot currentBallot = ballots.get(i);

            // Make proof statement
            List<Ciphertext> listCombinedCiphertext = Arrays.asList(previousObj.combinedCiphertext, currentObj.combinedCiphertext);
            List<Ciphertext> listCiphertexts = Arrays.asList(previousBallot.getEncryptedNegatedPrivateCredential(), currentBallot.getEncryptedNegatedPrivateCredential());

            // Verify proof
            boolean isValid = sigma4.verifyCombination(pk, listCombinedCiphertext, listCiphertexts, currentObj.proof, kappa);

            if(!isValid) {
                return false;
            }
        }

        return true;
    }

    public static boolean verifyDecryption(List<Ciphertext> ciphertexts, List<DecryptionShareAndProof> decryptionShareAndProofs, ElGamalPK pkShare, int kappa) {
        int ell = ciphertexts.size();
        Sigma3 sigma3 = new Sigma3();

        // Verify each entry
        for (int i = 0; i < ell; i++) {
            // Make proof statement
            Ciphertext ciphertext = ciphertexts.get(i);
            DecryptionShareAndProof decryptionShareAndProof = decryptionShareAndProofs.get(i);

            //Verify proof
            boolean isValid = sigma3.verifyDecryption(ciphertext, decryptionShareAndProof.share, pkShare, decryptionShareAndProof.proof, kappa);

            if (!isValid){
                return false;
            }
        }

        return true;
    }

    public static boolean verifyPK(List<CommitmentAndProof> commitmentAndProofs, Group group, int kappa) {
        Sigma1 sigma1 = new Sigma1();


        // Verify for every coefficient
        for (CommitmentAndProof comProof : commitmentAndProofs) {
            BigInteger commitment = comProof.commitment;
            Sigma1Proof rho = comProof.proof;
            boolean isValid = sigma1.VerifyKey(commitment, rho, group, kappa);

            if (!isValid){
                throw new RuntimeException(String.format("Malicious tallier detected. Tallier failed to prove their key"));
            }
        }
        return false;
    }

    public boolean verifyPK(BigInteger h, Sigma1Proof rho, Group group, int kappa) {
        Sigma1 sigma1 = new Sigma1();

        return sigma1.VerifyKey(h, rho, group, kappa);
    }


}
