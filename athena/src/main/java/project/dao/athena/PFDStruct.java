package project.dao.athena;

import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.CipherText;

import java.math.BigInteger;

public class PFDStruct {
    public final CipherText c_prime;
    public final BigInteger mv;
    public final Sigma4Proof omega;
    public final Sigma3Proof sigma_1;
    public final Sigma3Proof sigma_2;

    public PFDStruct(CipherText c_prime, BigInteger mv, Sigma4Proof omega, Sigma3Proof sigma_1, Sigma3Proof sigma_2) {
        this.c_prime = c_prime;
        this.mv = mv;
        this.omega = omega;
        this.sigma_1 = sigma_1;
        this.sigma_2 = sigma_2;
    }

    public PFDStruct(CipherText c_prime, BigInteger mv, Sigma4Proof omega, Sigma3Proof sigma_1) {
        this.c_prime = c_prime;
        this.mv = mv;
        this.omega = omega;
        this.sigma_1 = sigma_1;
        this.sigma_2 = null;
    }
}
