package cs.au.athena.dao.bulletinboard;

import cs.au.athena.dao.sigma1.Sigma1Proof;

import java.math.BigInteger;

public class CommitmentAndProof {
    public final BigInteger commitment;
    public final Sigma1Proof proof;

    public CommitmentAndProof(BigInteger commitment, Sigma1Proof proof) {
        this.commitment = commitment;
        this.proof = proof;
    }

    @Override
    public String toString() {
        return "Com&Proof{" + "com: " + commitment.toString().substring(0,5) + ", proof: " + proof + "}";

    }

}
