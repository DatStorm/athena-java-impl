package project.dao.sigma3;


import java.math.BigInteger;

public class Sigma3Proof {
    public final BigInteger a;
    public final BigInteger b;
    public final BigInteger r;

    public Sigma3Proof(BigInteger a, BigInteger b, BigInteger r) {
        this.a = a;
        this.b = b;
        this.r = r;
    }
}