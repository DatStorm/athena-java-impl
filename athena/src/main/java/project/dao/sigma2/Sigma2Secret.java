package project.dao.sigma2;

import java.math.BigInteger;

public class Sigma2Secret {
    public final BigInteger m;
    public final BigInteger r;

    public Sigma2Secret(BigInteger m, BigInteger r) {
        this.m = m;
        this.r = r;
    }
}
