package cs.au.athena.dao.Sigma2Pedersen;

import java.math.BigInteger;

public class Sigma2PedersenSecret {
    public final BigInteger w1, w2;

    public Sigma2PedersenSecret(BigInteger w1, BigInteger w2) {
        this.w1 = w1;
        this.w2 = w2;
    }


}
