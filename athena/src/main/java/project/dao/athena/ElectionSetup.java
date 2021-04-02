package project.dao.athena;

import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.math.BigInteger;

public class ElectionSetup {
    public final ElGamalSK sk;

    public ElectionSetup(ElGamalSK sk) {
        this.sk = sk;
    }
}
