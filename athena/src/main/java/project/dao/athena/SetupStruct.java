package project.dao.athena;

import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

public class SetupStruct {
    public final PK_Vector pkv;
    public final ElGamalSK sk;
    public final int mb;
    public final int mc;

    public SetupStruct(PK_Vector pkv, ElGamalSK sk, int mb, int mc) {

        this.pkv = pkv;
        this.sk = sk;
        this.mb = mb;
        this.mc = mc;
    }
}
