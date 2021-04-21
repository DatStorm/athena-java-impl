package cs.au.athena.dao.bulletinboard;

import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class PFR {
    public final List<CombinedCiphertextAndProof> listOfCombinedCiphertextAndProof;
    //public final List<Ciphertext> ciphertexts;
    //public final List<Sigma4Proof> homoCombProofs;


    public final BigInteger[] decryptionShares;
    public final Sigma3Proof[] decryptionProofs;

    public PFR(int tallierCount) {
        //ciphertexts = new ArrayList<>(tallierCount);
        //homoCombProofs = new ArrayList<>(tallierCount);
        listOfCombinedCiphertextAndProof = new ArrayList<>(tallierCount);
        decryptionShares = new BigInteger[tallierCount];
        decryptionProofs = new Sigma3Proof[tallierCount];
    }

    public List<CombinedCiphertextAndProof>  getCombinedCiphertext() {
        return this.listOfCombinedCiphertextAndProof;
    }



    public void setCiphertextCombinationAndProof(int tallierIndex, CombinedCiphertextAndProof combinedCiphertextAndProof) {
        assert combinedCiphertextAndProof.tallierIndex == tallierIndex;

        listOfCombinedCiphertextAndProof.add(combinedCiphertextAndProof);
    }

    public void setDecryptionShareAndProof(int tallierIndex, BigInteger decryptionShare, Sigma3Proof proof) {
        decryptionShares[tallierIndex] = decryptionShare;
        decryptionProofs[tallierIndex] = proof;
    }



}
