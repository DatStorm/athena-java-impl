package cs.au.athena.dao.sigma2;

import cs.au.athena.elgamal.Group;

import java.math.BigInteger;

public class ELStatement {
    public final BigInteger y1;
    public final BigInteger y2;
    public final BigInteger g1;
    public final BigInteger g2;
    public final BigInteger h1;
    public final BigInteger h2;
    public final Group group;

    public ELStatement(BigInteger y1, BigInteger y2, BigInteger g1, BigInteger g2, BigInteger h1, BigInteger h2, Group group ){
        this.y1 = y1;
        this.y2 = y2;
        this.g1 = g1;
        this.g2 = g2;
        this.h1 = h1;
        this.h2 = h2;
        this.group = group;
    }
}
