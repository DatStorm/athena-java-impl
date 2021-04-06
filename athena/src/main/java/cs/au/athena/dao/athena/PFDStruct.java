package cs.au.athena.dao.athena;

import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;

import java.math.BigInteger;

public class PFDStruct {
    enum Level {
        VALID,
        INVALID,
    }

    public final Level type;
    public final Ciphertext ciphertextCombination;
    public final BigInteger plaintext;
    public final Sigma4Proof proofCombination;
    public final Sigma3Proof proofDecryptionOfCombination;
    public final Sigma3Proof proofDecryptionVote;

    private PFDStruct(Level type, Ciphertext ciphertextCombination, BigInteger plaintext, Sigma4Proof proofCombination, Sigma3Proof proofDecryptionOfCombination, Sigma3Proof proofDecryptionVote) {
        this.type = type;
        this.ciphertextCombination = ciphertextCombination;
        this.plaintext = plaintext; // In this case this is the vote
        this.proofCombination = proofCombination;
        this.proofDecryptionOfCombination = proofDecryptionOfCombination;
        this.proofDecryptionVote = proofDecryptionVote;
    }

    // When m = 1
    public static PFDStruct newValid(Ciphertext ciphertextCombination, BigInteger plaintext, Sigma4Proof proofCombination, Sigma3Proof proofDecryptionOfCombination, Sigma3Proof proofDecryptionVote) {
        return new PFDStruct(
                Level.VALID,
                ciphertextCombination,
                plaintext,
                proofCombination,
                proofDecryptionOfCombination,
                proofDecryptionVote);
    }

    // When m != 1
    public static PFDStruct newInvalid(Ciphertext ciphertextCombination, BigInteger plaintext, Sigma4Proof proofCombination, Sigma3Proof proofDecryptionOfCombination) {
        return new PFDStruct(
                Level.INVALID,
                ciphertextCombination,
                plaintext,
                proofCombination,
                proofDecryptionOfCombination,
                null);
    }


    @Override
    public String toString() {
//        String substring = plaintext.toString().substring(0, 5);
        String substring = plaintext.toString();
        return "PFD{" + (type == Level.VALID ? "m=" : "v=") + substring + ", Sigma3.proofDec(...)^Comb: "+ proofDecryptionOfCombination.toString() + "}";


//        return "PFDStruct{" +
//                "ciphertextCombination=" + ciphertextCombination +
//                ", plaintext=" + plaintext +
//                ", proofCombination=" + proofCombination +
//                ", proofDecryptionOfCombination=" + proofDecryptionOfCombination +
//                ", proofDecryptionVote=" + proofDecryptionVote +
//                '}';
    }
}
