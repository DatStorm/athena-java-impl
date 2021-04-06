package project.dao.athena;

import elgamal.Ciphertext;

import java.math.BigInteger;

public class CredentialTuple { 
    public final Ciphertext publicCredential;
    public final BigInteger privateCredential;

    public CredentialTuple(Ciphertext publicCredential, BigInteger privateCredential) {
        this.publicCredential = publicCredential;
        this.privateCredential = privateCredential;
    }
}
