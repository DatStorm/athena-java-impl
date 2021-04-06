package project.dao.athena;

import project.dao.sigma1.ProveKeyInfo;
import elgamal.ElGamalPK;

public class PK_Vector {
    public final ElGamalPK pk;
    public final ProveKeyInfo rho;

    public PK_Vector(ElGamalPK pk, ProveKeyInfo rho) {

        this.pk = pk;
        this.rho = rho;
    }
}
