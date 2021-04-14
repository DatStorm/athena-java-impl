package cs.au.athena.dao.Sigma2Pedersen;

import java.math.BigInteger;

public class Sigma2PedersenSecret {
    public final BigInteger m, r;

    public Sigma2PedersenSecret(BigInteger m, BigInteger r) {
        this.m = m;
        this.r = r;
    }


}
