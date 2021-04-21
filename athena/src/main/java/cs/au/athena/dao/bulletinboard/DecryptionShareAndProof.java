package cs.au.athena.dao.bulletinboard;

import cs.au.athena.dao.sigma3.Sigma3Proof;

import java.math.BigInteger;

public class DecryptionShareAndProof {
    public final int tallierIndex;
    public final BigInteger share;
    public final Sigma3Proof proof;

    public DecryptionShareAndProof(int tallierIndex, BigInteger share, Sigma3Proof proof) {
        this.tallierIndex = tallierIndex;
        this.share = share;
        this.proof = proof;
    }


    public int getIndex() {
        return tallierIndex;
    }
}
