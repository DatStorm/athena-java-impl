package cs.au.athena.dao.athena;

import cs.au.athena.dao.sigma1.ProveKeyInfo;
import cs.au.athena.elgamal.ElGamalPK;

public class PK_Vector {
    public final ElGamalPK pk;
    public final ProveKeyInfo rho;

    public PK_Vector(ElGamalPK pk, ProveKeyInfo rho) {

        this.pk = pk;
        this.rho = rho;
    }
}
