package cs.au.athena.dao.bulletinboard;

import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;

public class CombinedCiphertextAndProof {
    public final Ciphertext combinedCiphertext;
    public final Sigma4Proof proof;

    public CombinedCiphertextAndProof(Ciphertext combinedCiphertext, Sigma4Proof proof) {
        this.combinedCiphertext = combinedCiphertext;
        this.proof = proof;
    }

    public Ciphertext getCombinedCiphertext() {
        return combinedCiphertext;
    }
}