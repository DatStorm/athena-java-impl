package project.dao.athena;

import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.math.BigInteger;

public class SetupStruct {
    public final PK_Vector pkv;
    public final ElGamalSK sk;
    public final int mb;
    public final BigInteger mc;

    public SetupStruct(PK_Vector pkv, ElGamalSK sk, int mb, BigInteger mc) {

        this.pkv = pkv;
        this.sk = sk;
        this.mb = mb;
        this.mc = mc;
    }
}
