package project.dao.sigma1;

import elgamal.ElGamalPK;

public class PublicInfoSigma1 {
    private final int kappa;
    private final ElGamalPK pk;

    public PublicInfoSigma1(int kappa, ElGamalPK pk) {
        this.kappa = kappa;
        this.pk = pk;
    }

    public ElGamalPK getPK() {
        return this.pk;
    }
}
