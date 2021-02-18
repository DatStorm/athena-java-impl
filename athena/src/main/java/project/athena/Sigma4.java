package project.athena;

import project.UTIL;
import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma3.Sigma3Statement;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.elgamal.GroupDescription;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Sigma4 {
    private final Sigma3 sigma3;
    private MessageDigest hashH;

    public Sigma4(MessageDigest hashH) {
        this.hashH = hashH;
        this.sigma3 = new Sigma3(this.hashH);
    }

    public Sigma4Proof proveCombination(ElGamalSK sk, List<CipherText> c0_c1, List<CipherText> b0_b1, int nonce_n, int kappa) {
        ArrayList<Sigma3Proof> alpha_beta_omegaProofs = new ArrayList<>();
        ArrayList<Sigma3Proof> alpha_alpha_omegaProofs = new ArrayList<>();

        assert c0_c1.size() == b0_b1.size() : "c0_c1.size() != b0_b1.size()";

        GroupDescription group = sk.getPK().getGroup();

        /*
         * SIGMA 3 (1)
         * log_ai' a_i = log_bi' bi
         */
        // Prove that the same nonce was used in both parts of the new ciphertext
        for (int i = 0; i < c0_c1.size(); i++) {
            CipherText c = c0_c1.get(i);
            CipherText b = b0_b1.get(i);

            // Prove log equality
            Sigma3Statement statement = new Sigma3Statement(group, c.c1, c.c2, b.c1, b.c2);
//            System.out.println("Sigma4.proveCombination: " + statement);
            //Sigma3Statement statement = createSigma3Statement(group, c, b);
            Sigma3Proof omega_proof1 = sigma3.proveLogEquality(statement, sk, kappa);
            alpha_beta_omegaProofs.add(omega_proof1);
        }

        // Prove that the same nonce was used on each ballot
        // NOTE WE START AT 1
        for (int i = 1; i < c0_c1.size(); i++) {
            CipherText c_previous = c0_c1.get(i - 1);
            CipherText c = c0_c1.get(i);
            CipherText b_previous = b0_b1.get(i - 1);
            CipherText b = b0_b1.get(i);

            // Proove log equality
            Sigma3Statement statement = new Sigma3Statement(group, c_previous.c1, c.c1, b_previous.c1, b.c1);
            //Sigma3Statement statement = createSigma3Statement(group, c_previous, c);
            Sigma3Proof omega_proof2 = sigma3.proveLogEquality(statement, sk, kappa);
            alpha_alpha_omegaProofs.add(omega_proof2);
        }

        return new Sigma4Proof(alpha_beta_omegaProofs, alpha_alpha_omegaProofs);
    }

    // Creates the statement for prooving log equality
    private Sigma3Statement createSigma3Statement(GroupDescription group, CipherText a, CipherText b) {
        BigInteger alpha = a.c1;
        BigInteger beta = a.c2;
        BigInteger alpha_base = b.c1;
        BigInteger beta_base = b.c2;

        return new Sigma3Statement(group, alpha, beta, alpha_base, beta_base);
    }

    public boolean verifyCombination(ElGamalPK pk, List<CipherText> c0_c1, List<CipherText> b0_b1, Sigma4Proof proof, int kappa) {
        GroupDescription group = pk.getGroup();

        int size = c0_c1.size();
        assert size == b0_b1.size() : "c0_c1.size() != b0_b1.size()";
        assert size == proof.getAlphaBetaProof().size() : "c0_c1.size() != proof.getAlphaBetaProof().size()";
        assert size-1 == proof.getAlphaAlphaProof().size() : "b0_b1.size() != proof.getAlphaAlphaProof().size()";

        // verify log_ai' ai != log_bi' bi
        for (int i = 0; i < c0_c1.size(); i++) {
            CipherText c = c0_c1.get(i);
            CipherText b = b0_b1.get(i);

            // Prove log equality
            Sigma3Statement statement = new Sigma3Statement(group, c.c1, c.c2, b.c1, b.c2);
//            System.out.println("Sigma4.verifyCombination: " + statement);

            /////// ANDERS!!!
            //Sigma3Statement statement = createSigma3Statement(group, c, b);
            Sigma3Proof proof_i = proof.getAlphaBetaProof().get(i);

            boolean isValid = sigma3.verifyLogEquality(statement, proof_i, kappa);

            if(!isValid) {
                System.err.println("Sigma4.verifyCombination-> log_ai' ai != log_bi' bi");
                System.out.println("PARAMS:\n " + pk + ", \nc0_c1 = " + Arrays.toString(c0_c1.toArray()) + ", \nb0_b1 = " + Arrays.toString(b0_b1.toArray()) + ", \nproof = " + proof + ", \nkappa = " + kappa);
                System.out.println("--------------------------");
                UTIL.CompareElGamalGroup(pk.getGroup(),statement.getGroup());
                System.out.println("Statement: "+ statement + "\nproof_i=:" + proof_i + "isvalid: " + isValid);
                return false;
            }
        }

        /*******************************************************************************/
        // Verify log_a'_{i-1} a_{i-1} != log_ai' ai
        // Prove that the same nonce was used on each ballot
        // NOTE WE START AT 1
        for (int i = 1; i < c0_c1.size(); i++) {
            CipherText c_previous = c0_c1.get(i - 1);
            CipherText c = c0_c1.get(i);
            CipherText b_previous = b0_b1.get(i - 1);
            CipherText b = b0_b1.get(i);

            // Proove log equality
            Sigma3Statement statement = new Sigma3Statement(group, c_previous.c1, c.c1, b_previous.c1, b.c1);
            Sigma3Proof proofi = proof.getAlphaAlphaProof().get(i-1);
            boolean isValid = sigma3.verifyLogEquality(statement, proofi, kappa);

            if(!isValid){
                System.err.println("Sigma4.verifyCombination-> log_a'_{i-1} a_{i-1} != log_ai' ai");
                return false;
            }

        }


        return true;
    }
}
