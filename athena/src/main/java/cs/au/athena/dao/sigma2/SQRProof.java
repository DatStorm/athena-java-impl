package cs.au.athena.dao.sigma2;

import java.math.BigInteger;

public class SQRProof {
    public final BigInteger y2;
    public final BigInteger c;
    public final BigInteger D;
    public final BigInteger D1;
    public final BigInteger D2;

    public SQRProof(BigInteger y2, BigInteger c, BigInteger d, BigInteger d1, BigInteger d2) {
        this.y2 = y2;
        this.c = c;
        D = d;
        D1 = d1;
        D2 = d2;
    }
}
