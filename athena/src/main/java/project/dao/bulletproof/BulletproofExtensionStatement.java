package project.dao.bulletproof;

import project.elgamal.ElGamalPK;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.List;

public class BulletproofExtensionStatement extends BulletproofStatement {
    public final BigInteger H;

    public BulletproofExtensionStatement(BigInteger H, BigInteger V, ElGamalPK pk, List<BigInteger> g_vector, List<BigInteger> h_vector) {
        super(Bulletproof.getN(H), V, pk, g_vector, h_vector);
        this.H = H; // represents the range [0;H]


        int n = Bulletproof.getN(H);
        assert g_vector.size() == n;
        assert h_vector.size() == n;
    }


}
