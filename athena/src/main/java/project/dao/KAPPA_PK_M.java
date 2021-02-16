package project.dao;

import project.elgamal.ElGamalPK;

public class KAPPA_PK_M {
    private final int kappa;
    private final ElGamalPK pk;
    private final FRAKM frakm;

    public KAPPA_PK_M(int kappa, ElGamalPK pk, FRAKM frakm) {

        this.kappa = kappa;
        this.pk = pk;
        this.frakm = frakm;
    }
}
