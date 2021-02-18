package project.athena;

import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma3.Sigma3Statement;
import project.dao.sigma4.CombinationProof;
import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.List;

public class Sigma4 {
    private final Sigma3 sigma3;
    private MessageDigest hashH;

    public Sigma4(MessageDigest hashH) {
        this.hashH = hashH;
        this.sigma3 = new Sigma3(this.hashH);
    }

    public CombinationProof proveCombination(ElGamalSK sk, List<CipherText> c0_c1, List<CipherText> b0_b1, int nonce_n, int kappa) {

        /*
         * SIGMA 3 (1)
         * log_ai' a_i = log_bi' bi
        */
        // Prove that the same nonce was used in both parts of the new ciphertext
        for (int i = 0; i < c0_c1.size(); i++) {
            CipherText c = c0_c1.get(i);
            CipherText b = b0_b1.get(i);

            BigInteger alpha = c.c1;
            BigInteger beta = c.c2;
            BigInteger alpha_base = b.c1;
            BigInteger beta_base = b.c2;

            // Proove log equality
            Sigma3Statement info = new Sigma3Statement(sk.getPK().getGroup(), alpha, beta, alpha_base, beta_base);
            Sigma3Proof proof = sigma3.proveLogEquality(info, sk, kappa);
        }

        // Prove that the same nonce was used on each ballot
        for (int i = 1; i < c0_c1.size(); i++) {
            CipherText c_previous = c0_c1.get(i-1);
            CipherText c = c0_c1.get(i);

            BigInteger alpha = c_previous.c1;
            BigInteger beta = c_previous.c2;
            BigInteger alpha_base = c.c1;
            BigInteger beta_base = c.c2;

            // Proove log equality
            Sigma3Statement info = new Sigma3Statement(sk.getPK().getGroup(), alpha, beta, alpha_base, beta_base);
            Sigma3Proof proof = sigma3.proveLogEquality(info, sk, kappa);
        }
        
        


        return null;
    }
}
