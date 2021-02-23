package project.sigma;

import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma3.Sigma3Statement;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.elgamal.Group;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class Sigma4 {
    private final Sigma3 sigma3;
    private MessageDigest hashH;

    public Sigma4(MessageDigest hashH) {
        this.hashH = hashH;
        this.sigma3 = new Sigma3(this.hashH);
    }

    /*
    * secret key sk
    * homo comb c0_c1 of b0_b1
    */
    // (c1',c2') = (c1,c2)^n
    //combinedCiphertextList, //originCiphertextList
    public Sigma4Proof proveCombination(ElGamalSK sk, List<CipherText> listOfcombinedCiphertext, List<CipherText> listOfCiphertexts, int nonce_n, int kappa) {
        ArrayList<Sigma3Proof> alpha_beta_omegaProofs = new ArrayList<>();
        ArrayList<Sigma3Proof> alpha_alpha_omegaProofs = new ArrayList<>();

        // we must have pairs of homo comb and single ciphertexts
        assert listOfcombinedCiphertext.size() == listOfCiphertexts.size() : "c0_c1.size() != b0_b1.size()";

        Group group = sk.getPK().getGroup();

        /*
         * SIGMA 3 (1)
         * log_{alpha_base_i} alpha_{i} != log_{beta_base_i} beta_{i}
         */
        // Prove that the same nonce was used in both parts of the new ciphertext
        for (int i = 0; i < listOfcombinedCiphertext.size(); i++) {
            CipherText c = listOfcombinedCiphertext.get(i);
            CipherText b = listOfCiphertexts.get(i);

            // Prove log equality
            Sigma3Statement statement = new Sigma3Statement(group, c.c1, c.c2, b.c1, b.c2);
//            System.out.println("Sigma4.proveCombination: " + statement);
            //Sigma3Statement statement = createSigma3Statement(group, c, b);
            Sigma3Proof omega_proof1 = sigma3.proveLogEquality(statement, BigInteger.valueOf(nonce_n), kappa);
            alpha_beta_omegaProofs.add(omega_proof1);
        }

        // Prove that the same nonce was used on each ballot
        // NOTE WE START AT 1
        for (int i = 1; i < listOfcombinedCiphertext.size(); i++) {
            CipherText c_previous = listOfcombinedCiphertext.get(i - 1);
            CipherText c = listOfcombinedCiphertext.get(i);
            CipherText b_previous = listOfCiphertexts.get(i - 1);
            CipherText b = listOfCiphertexts.get(i);

            // Proove log equality
            Sigma3Statement statement = new Sigma3Statement(group, c_previous.c1, c.c1, b_previous.c1, b.c1);
            //Sigma3Statement statement = createSigma3Statement(group, c_previous, c);
            Sigma3Proof omega_proof2 = sigma3.proveLogEquality(statement, BigInteger.valueOf(nonce_n), kappa);
            alpha_alpha_omegaProofs.add(omega_proof2);
        }

        return new Sigma4Proof(alpha_beta_omegaProofs, alpha_alpha_omegaProofs);
    }

    // Creates the statement for prooving log equality
    /*
    private Sigma3Statement createSigma3Statement(GroupDescription group, CipherText a, CipherText b) {
        BigInteger alpha = a.c1;
        BigInteger beta = a.c2;
        BigInteger alpha_base = b.c1;
        BigInteger beta_base = b.c2;

        return new Sigma3Statement(group, alpha, beta, alpha_base, beta_base);
    }
    */

   /*
    * secret key sk
    * homo comb combinedCiphertextList of b0_b1
    */

    public boolean verifyCombination(ElGamalPK pk, List<CipherText> combinedCiphertextList, List<CipherText> listOfCipherTexts, Sigma4Proof proof, int kappa) {
        Group group = pk.getGroup();

        int size = combinedCiphertextList.size();
        assert size == listOfCipherTexts.size() : "combinedCiphertextList.size() != b0_b1.size()";
        assert size == proof.getAlphaBetaProof().size() : "combinedCiphertextList.size() != proof.getAlphaBetaProof().size()";
        assert size - 1 == proof.getAlphaAlphaProof().size() : "listOfCipherTexts.size() != proof.getAlphaAlphaProof().size()";

        // verify log_{alpha_base_i} alpha_{i} != log_{beta_base_i} beta_{i}
        for (int i = 0; i < combinedCiphertextList.size(); i++) {
            CipherText c = combinedCiphertextList.get(i);
            CipherText b = listOfCipherTexts.get(i);

            // Prove log equality
            Sigma3Statement statement = new Sigma3Statement(group, c.c1, c.c2, b.c1, b.c2);

            Sigma3Proof proof_i = proof.getAlphaBetaProof().get(i);
            boolean isValid = sigma3.verifyLogEquality(statement, proof_i, kappa);

            if (!isValid) {
//                System.out.println("Sigma4.verifyCombination-> log_{alpha_base_i} alpha_{i} != log_{beta_base_i} beta_{i}");
                return false;
            }
        }

        /*******************************************************************************/
        // Verify log_{alpha_base_i-1} alpha_{i-1} != log_{alpha_base_i} alpha_{i}
        // Prove that the same nonce was used on each ballot
        // NOTE WE START AT 1
        for (int i = 1; i < combinedCiphertextList.size(); i++) {
            CipherText c_previous = combinedCiphertextList.get(i - 1);
            CipherText c = combinedCiphertextList.get(i);
            CipherText b_previous = listOfCipherTexts.get(i - 1);
            CipherText b = listOfCipherTexts.get(i);

            // Proove log equality
            Sigma3Statement statement = new Sigma3Statement(group, c_previous.c1, c.c1, b_previous.c1, b.c1);
            Sigma3Proof proofi = proof.getAlphaAlphaProof().get(i - 1);
            boolean isValid = sigma3.verifyLogEquality(statement, proofi, kappa);

            if (!isValid) {
//                System.out.println("--> Sigma4.verifyCombination-> log_{alpha_base_i-1} alpha_{i-1} != log_{alpha_base_i} alpha_{i}");
                return false;
            }
        }
        return true;
    }

}


//                System.out.println("PARAMS:\n " + pk + ", \ncombinedCiphertextList = " + Arrays.toString(combinedCiphertextList.toArray()) + ", \nb0_b1 = " + Arrays.toString(listOfCipherTexts.toArray()) + ", \nproof = " + proof + ", \nkappa = " + kappa);
//                System.out.println("--------------------------");
//                UTIL.CompareElGamalGroup(pk.getGroup(), statement.getGroup());
//                System.out.println("Statement: " + statement + "\nproof_i=:" + proof_i + "isvalid: " + isValid);

//        System.out.println("proveCombination() => group = " + sk.getPK().getGroup() + ", alpha = " + alpha + ", beta = " + beta + ", alpha_base = " + alpha_base + ", beta_base = " + beta_base);
//
//                System.out.println("---> alpha: " + UTIL.BigLog(alpha_base,alpha));
//                System.out.println("---> beta: " + UTIL.BigLog(beta_base,beta));