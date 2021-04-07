package cs.au.athena.dao.Sigma2Pedersen;

import cs.au.athena.dao.athena.UVector;
import cs.au.athena.elgamal.Group;

import java.math.BigInteger;

public class Sigma2PedersenStatement {
    public final BigInteger g, h, C;
    public final UVector uvector;
    public final Group group;

    public Sigma2PedersenStatement(BigInteger g, BigInteger h, BigInteger C, UVector uvector, Group group) {
        this.g = g;
        this.h = h;
        this.C = C;
        this.uvector = uvector;
        this.group = group;

    }
}
