package project.dao.athena;

import project.elgamal.CipherText;

public class RegisterStruct {
    public final CipherText pd;
    public final D_Vector d;

    public RegisterStruct(CipherText pd, D_Vector d) {
        this.pd = pd;
        this.d = d;
    }
}
