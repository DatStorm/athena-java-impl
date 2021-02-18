package project.athena;

import project.dao.sigma4.CombinationProof;
import project.elgamal.CipherText;
import project.elgamal.ElGamalPK;

import java.security.MessageDigest;

public class Sigma4 {
    private MessageDigest hashH;

    public Sigma4(MessageDigest hashH) {

        this.hashH = hashH;
    }

    public CombinationProof proveCombination(ElGamalPK pk, CipherText c0, CipherText c1, CipherText b0, CipherText b1, int nonce_n, int kappa) {
        return null;
    }
}
