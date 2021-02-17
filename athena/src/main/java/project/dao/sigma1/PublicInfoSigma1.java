package project.dao.sigma1;

import project.dao.FRAKM;
import project.elgamal.ElGamalPK;

public class PublicInfoSigma1 {
    private final int kappa;
    private final ElGamalPK pk;
    private final FRAKM frakm;

    public PublicInfoSigma1(int kappa, ElGamalPK pk, FRAKM frakm) {

        this.kappa = kappa;
        this.pk = pk;
        this.frakm = frakm;
    }

    public ElGamalPK getPK() {
        return this.pk;
    }
}
