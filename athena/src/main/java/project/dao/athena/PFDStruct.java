package project.dao.athena;

import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.Ciphertext;

import java.math.BigInteger;

public class PFDStruct {
    public final Ciphertext ciphertextCombination;
    public final BigInteger plaintext;
    public final Sigma4Proof proofCombination;
    public final Sigma3Proof proofDecryptionOfCombination;
    public final Sigma3Proof proofDecryptionVote;
    private final boolean isM;


    public PFDStruct(Ciphertext ciphertextCombination, BigInteger plaintext, Sigma4Proof proofCombination, Sigma3Proof proofDecryptionOfCombination, Sigma3Proof proofDecryptionVote) {
        this.ciphertextCombination = ciphertextCombination;
        this.plaintext = plaintext; // In this case this is the vote
        this.proofCombination = proofCombination;
        this.proofDecryptionOfCombination = proofDecryptionOfCombination;
        this.proofDecryptionVote = proofDecryptionVote;
        this.isM = true;
    }
    
    public PFDStruct(Ciphertext ciphertextCombination, BigInteger plaintext, Sigma4Proof proofCombination, Sigma3Proof proofDecryptionOfCombination) {
        this.ciphertextCombination = ciphertextCombination;
        this.plaintext = plaintext; // In this case this is m
        this.proofCombination = proofCombination;
        this.proofDecryptionOfCombination = proofDecryptionOfCombination;
        this.proofDecryptionVote = null; //FIXME: handle this better
        this.isM = false;

    }


    @Override
    public String toString() {

        return "PFD{" + (isM ? "m=" : "v=") + plaintext.toString().substring(0,5) + "}";


//        return "PFDStruct{" +
//                "ciphertextCombination=" + ciphertextCombination +
//                ", plaintext=" + plaintext +
//                ", proofCombination=" + proofCombination +
//                ", proofDecryptionOfCombination=" + proofDecryptionOfCombination +
//                ", proofDecryptionVote=" + proofDecryptionVote +
//                '}';
    }
}
