package project.dao.sigma3;


import java.math.BigInteger;

public class DecryptionProof {
    public final BigInteger a;
    public final BigInteger b;
    public final BigInteger r;

    public DecryptionProof(BigInteger a, BigInteger b, BigInteger r) {
        this.a = a;
        this.b = b;
        this.r = r;
    }
}