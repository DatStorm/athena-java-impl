package cs.au.athena.dao.bulletinboard;

import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;

public class CombinedCiphertextAndProof {
    public final int tallierIndex;
    public final Ciphertext combinedCiphertext;
    public final Sigma4Proof proof;

    public CombinedCiphertextAndProof(int tallierIndex, Ciphertext combinedCiphertext, Sigma4Proof proof) {
        this.tallierIndex = tallierIndex;
        this.combinedCiphertext = combinedCiphertext;
        this.proof = proof;
    }

}