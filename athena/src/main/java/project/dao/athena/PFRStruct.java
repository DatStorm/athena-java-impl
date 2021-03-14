package project.dao.athena;

import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.Ciphertext;

import java.math.BigInteger;

public class PFRStruct {
    public final Ciphertext ciphertextCombination;
    public final BigInteger plaintext_N;
    public final Sigma3Proof proofDecryption;
    public final Sigma4Proof proofCombination;

    public PFRStruct(Ciphertext ciphertextCombination, BigInteger plaintext_N, Sigma3Proof proofDecryption) {
        this.ciphertextCombination = ciphertextCombination;
        this.plaintext_N = plaintext_N;
        this.proofDecryption = proofDecryption;
        this.proofCombination = null;
    }

    public PFRStruct(Ciphertext ciphertextCombination, BigInteger plaintext_N, Sigma3Proof proofDecryption, Sigma4Proof proofCombination) {

        this.ciphertextCombination = ciphertextCombination;
        this.plaintext_N = plaintext_N;
        this.proofDecryption = proofDecryption;
        this.proofCombination = proofCombination;
    }

    @Override
    public String toString() {

        return "PFR{" + "N=" + plaintext_N.toString().substring(0,5) + "..." + "}";
//        return "PFRStruct{" +
//                "ciphertextCombination=" + ciphertextCombination +
//                ", plaintext_N=" + plaintext_N +
//                ", proofDecryption=" + proofDecryption +
//                ", proofCombination=" + proofCombination +
//                '}';
    }
}
