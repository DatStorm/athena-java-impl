package project.dao.athena;

import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.math.BigInteger;

public class ElectionSetup {
    public final PK_Vector pkv;
    public final ElGamalSK sk;
    public final int mb;
    public final BigInteger mc;
    public final int nc;

    public ElectionSetup(PK_Vector pkv, ElGamalSK sk, int mb, BigInteger mc, int nc) {

        this.pkv = pkv;
        this.sk = sk;
        this.mb = mb;
        this.mc = mc;
        this.nc = nc;
    }
}
