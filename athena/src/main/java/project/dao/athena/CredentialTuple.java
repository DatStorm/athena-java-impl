package project.dao.athena;

import project.elgamal.CipherText;

import java.math.BigInteger;

public class CredentialTuple { 
    public final CipherText publicCredential; 
    public final BigInteger privateCredential;

    public CredentialTuple(CipherText publicCredential, BigInteger privateCredential) {
        this.publicCredential = publicCredential;
        this.privateCredential = privateCredential;
    }
}
