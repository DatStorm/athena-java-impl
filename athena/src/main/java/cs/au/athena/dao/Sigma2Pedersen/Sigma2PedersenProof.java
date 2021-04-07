package cs.au.athena.dao.Sigma2Pedersen;

import java.math.BigInteger;

public class Sigma2PedersenProof{
    public final BigInteger a, z1, z2;

    public Sigma2PedersenProof(BigInteger a, BigInteger z1, BigInteger z2) {
        this.a = a;
        this.z1 = z1;
        this.z2 = z2;
    }

    @Override
    public String toString() {
        return "Sigma2PedersenProof{" +
                "a=" + a +
                ", z1=" + z1 +
                ", z2=" + z2 +
                '}';
    }
}