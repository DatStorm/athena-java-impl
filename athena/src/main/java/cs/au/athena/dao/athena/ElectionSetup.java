package cs.au.athena.dao.athena;

import cs.au.athena.elgamal.ElGamalSK;

public class ElectionSetup {
    public final ElGamalSK sk;

    public ElectionSetup(ElGamalSK sk) {
        this.sk = sk;
    }
}
