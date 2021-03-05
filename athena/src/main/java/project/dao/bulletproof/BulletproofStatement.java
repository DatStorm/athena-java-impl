package project.dao.bulletproof;

public class BulletproofStatement {
    public final int n;
    public final BigInteger V; // commitment 
    public final ElGamalPK pk;



    public BulletproofStatement(BigInteger n, BigInteger V, ElGamalPK pk) {
        this.n = n;
        this.V = V;
        this.pk = pk; 
    }
}
