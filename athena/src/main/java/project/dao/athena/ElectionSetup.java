package project.dao.athena;

import elgamal.ElGamal;
import elgamal.ElGamalPK;
import elgamal.ElGamalSK;

public class ElectionSetup {
    public final ElGamalSK sk;

    public ElectionSetup(ElGamalSK sk) {
        this.sk = sk;
    }
}
