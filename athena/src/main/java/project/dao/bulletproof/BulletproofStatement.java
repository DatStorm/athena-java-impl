package project.dao.bulletproof;

import project.elgamal.ElGamalPK;

import java.math.BigInteger;
import java.util.List;

public class BulletproofStatement {
    public final int n;
    public final BigInteger V; // commitment
    public final ElGamalPK pk;
    public final List<BigInteger> g_vector;
    public final List<BigInteger> h_vector;


    public BulletproofStatement(int n, BigInteger V, ElGamalPK pk, List<BigInteger> g_vector, List<BigInteger> h_vector) {
        this.n = n;
        this.V = V;
        this.pk = pk;
        this.g_vector = g_vector;
        this.h_vector = h_vector;
    }
}
