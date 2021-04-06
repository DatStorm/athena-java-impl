package cs.au.athena.dao.bulletproof;

import java.math.BigInteger;

public class BulletproofSecret {
    public BigInteger m;
    public BigInteger gamma;

    public BulletproofSecret(BigInteger m, BigInteger gamma){
        this.m = m;
        this.gamma = gamma;
    }
}
