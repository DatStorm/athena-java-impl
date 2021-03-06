package cs.au.athena.dao.bulletinboard;

import cs.au.athena.dao.sigma3.Sigma3Proof;

import java.math.BigInteger;

public class DecryptionShareAndProof {
    public final BigInteger share;
    public final Sigma3Proof proof;

    public DecryptionShareAndProof(BigInteger share, Sigma3Proof proof) {
        this.share = share;
        this.proof = proof;
    }

    public BigInteger getShare() {
        return share;
    }
}
