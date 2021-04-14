package cs.au.athena.dao.sigma2;

import java.math.BigInteger;

public class SQRSecret {
    public final BigInteger x;
    public final BigInteger r;

    public SQRSecret(BigInteger x, BigInteger r) {
        this.x = x;
        this.r = r;
    }
}
