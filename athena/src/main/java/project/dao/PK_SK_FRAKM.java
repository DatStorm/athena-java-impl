package project.dao;

import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

public class PK_SK_FRAKM {
    private final ElGamalPK pk;
    private final ElGamalSK sk;
    private final FRAKM frakm;

    public PK_SK_FRAKM(ElGamalPK pk, ElGamalSK sk, FRAKM frakm) {

        this.pk = pk;
        this.sk = sk;
        this.frakm = frakm;
    }

    public ElGamalSK getSK() {
        return this.sk;
    }

    public ElGamalPK getPK() {
        return this.pk;
    }

    public FRAKM getFRAKM() {
        return this.frakm;
    }
}
