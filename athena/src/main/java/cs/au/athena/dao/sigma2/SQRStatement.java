package cs.au.athena.dao.sigma2;

import cs.au.athena.elgamal.Group;

import java.math.BigInteger;

public class SQRStatement {
    public final BigInteger g;
    public final BigInteger h;
    public final BigInteger y1;
    public final Group group;

    public SQRStatement(BigInteger g, BigInteger h, BigInteger y1, Group group) {
        this.g = g;
        this.h = h;
        this.y1 = y1;
        this.group = group;
    }
}
