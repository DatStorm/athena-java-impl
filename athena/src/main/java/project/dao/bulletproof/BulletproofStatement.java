package project.dao.bulletproof;

import project.elgamal.ElGamalPK;

import java.math.BigInteger;

public class BulletproofStatement {
    public final int n;
    public final BigInteger V; // commitment
    public final ElGamalPK pk;



    public BulletproofStatement(int n, BigInteger V, ElGamalPK pk) {
        this.n = n;
        this.V = V;
        this.pk = pk; 
    }
}
