package cs.au.athena.dao.athena;

import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;
import java.util.List;
import java.util.ArrayList;

import java.math.BigInteger;

public class PFRStruct {
    // Each tallier will post the following fields as the get to it.
    public final List<Ciphertext> ciphertextCombination;
    public final List<BigInteger> plaintext_N;
    public final List<Sigma3Proof> proofDecryption;
    public final List<Sigma4Proof> proofCombination;

    public PFRStruct() {
        this.ciphertextCombination = new ArrayList<>();
        this.plaintext_N = new ArrayList<>();
        this.proofDecryption = new ArrayList<>();
        this.proofCombination = new ArrayList<>();
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
