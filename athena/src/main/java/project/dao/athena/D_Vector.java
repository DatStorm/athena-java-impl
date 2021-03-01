package project.dao.athena;

import project.elgamal.CipherText;

public class D_Vector {
    public final CipherText pd;
    public final int d;

    public D_Vector(CipherText pd, int d) {
        this.pd = pd;
        this.d = d;
    }
}
