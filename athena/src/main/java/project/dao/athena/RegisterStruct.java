package project.dao.athena;

import elgamal.Ciphertext;

public class RegisterStruct {
    public final Ciphertext pd;
    public final CredentialTuple d;

    public RegisterStruct(Ciphertext pd, CredentialTuple d) {
        this.pd = pd;
        this.d = d;
    }
}
