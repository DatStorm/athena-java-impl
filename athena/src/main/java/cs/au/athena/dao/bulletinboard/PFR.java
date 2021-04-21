package cs.au.athena.dao.bulletinboard;

import cs.au.athena.dao.sigma3.Sigma3Proof;
import cs.au.athena.dao.sigma4.Sigma4Proof;
import cs.au.athena.elgamal.Ciphertext;

import java.math.BigInteger;

public class PFR {
    public final Ciphertext[] ciphertexts;
    public final Sigma4Proof[] homoCombProofs;

    public final BigInteger[] decryptionShares;
    public final Sigma3Proof[] decryptionProofs;

    public PFR(int tallierCount) {
        ciphertexts = new Ciphertext[tallierCount];
        homoCombProofs = new Sigma4Proof[tallierCount];
        decryptionShares = new BigInteger[tallierCount];
        decryptionProofs = new Sigma3Proof[tallierCount];
    }

    public void setCombination(int tallierIndex, Ciphertext ciphertext, Sigma4Proof proof) {
        ciphertexts[tallierIndex] = ciphertext;
        homoCombProofs[tallierIndex] = proof;
    }

    public void setDecryption(int tallierIndex, BigInteger decryptionShare, Sigma3Proof proof) {
        decryptionShares[tallierIndex] = decryptionShare;
        decryptionProofs[tallierIndex] = proof;
    }



}
