package cs.au.athena.dao.Sigma2Pedersen;

import cs.au.athena.elgamal.Group;

import java.math.BigInteger;

public class Sigma2PedersenStatement {
    public final BigInteger g1, g2, C;
    public final Group group;

    public Sigma2PedersenStatement(BigInteger g1, BigInteger g2, BigInteger C, Group group) {
        this.g1 = g1;
        this.g2 = g2;
        this.C = C;
        this.group = group;

    }
}
