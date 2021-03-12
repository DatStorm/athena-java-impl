package project.dao.athena;

import project.elgamal.CipherText;

public class RegisterStruct {
    public final CipherText pd;
    public final CredentialTuple d;

    public RegisterStruct(CipherText pd, CredentialTuple d) {
        this.pd = pd;
        this.d = d;
    }
}
