package cs.au.athena.dao.bulletinboard;

import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;

public class HomoCombinationAndProof {
    Ciphertext combinedCiphertext;
    Sigma4Proof proof;

    public HomoCombinationAndProof(Ciphertext combinedCiphertext, Sigma4Proof proof) {
        this.combinedCiphertext = combinedCiphertext;
        this.proof = proof;
    }
}
