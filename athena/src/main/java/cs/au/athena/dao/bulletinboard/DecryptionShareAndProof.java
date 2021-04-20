package cs.au.athena.dao.bulletinboard;

import cs.au.athena.dao.sigma3.Sigma3Proof;
import java.math.BigInteger;


public class DecryptionShareAndProof {// Decryption shares
    public final int index;
    public final BigInteger share;
    public final Sigma3Proof proof;

    public DecryptionShareAndProof(int index, BigInteger share, Sigma3Proof proof) {
        this.index = index;
        this.share = share;
        this.proof = proof;
    }

    public int getIndex() {
        return index;
    }

    public BigInteger getShare() {
        return share;
    }

    public Sigma3Proof getProof() {
        return proof;
    }
}
