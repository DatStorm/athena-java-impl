package cs.au.athena.dao.athena;

import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.elgamal.ElGamalPK;

public class PK_Vector {
    public final ElGamalPK pk;
    public final Sigma1Proof rho;

    public PK_Vector(ElGamalPK pk, Sigma1Proof rho) {

        this.pk = pk;
        this.rho = rho;
    }
}
