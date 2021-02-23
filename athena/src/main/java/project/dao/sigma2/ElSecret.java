package project.dao.sigma2;

import java.math.BigInteger;

public class ElSecret {
    public final BigInteger x;
    public final BigInteger r1;
    public final BigInteger r2;

    public ElSecret(BigInteger x, BigInteger r1, BigInteger r2) {
        this.x = x;
        this.r1 = r1;
        this.r2 = r2;
    }
}
