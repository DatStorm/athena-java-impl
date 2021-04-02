package project.dao.sigma2;

import project.elgamal.Group;
import project.elgamal.ElGamalPK;

import java.math.BigInteger;

public class Sigma2Statement {
    public final BigInteger c;
    public final BigInteger a;
    public final BigInteger b;
    public final ElGamalPK pk;



    public Sigma2Statement(BigInteger c, BigInteger a, BigInteger b, ElGamalPK pk) {
        this.c = c;
        this.a = a;
        this.b = b;
        this.pk = pk; 
    }
}
