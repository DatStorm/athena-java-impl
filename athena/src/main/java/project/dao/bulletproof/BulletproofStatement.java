package project.dao.bulletproof;

import project.elgamal.ElGamalPK;

import java.math.BigInteger;
import java.util.List;

public class BulletproofStatement {
    public final Integer n;
    public final BigInteger V; // commitment
    public final ElGamalPK pk;
    public final List<BigInteger> g_vector;
    public final List<BigInteger> h_vector;


    public BulletproofStatement(Integer n, BigInteger V, ElGamalPK pk, List<BigInteger> g_vector, List<BigInteger> h_vector) {
        this.n = n;
        this.V = V; // commitment V = g^m h^\gamma.
        this.pk = pk;
        this.g_vector = g_vector;
        this.h_vector = h_vector;
    }
}
