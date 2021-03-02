package project.dao.athena;

import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.CipherText;

import java.math.BigInteger;

public class PFRStruct {
    public final CipherText ci_prime;
    public final BigInteger n;
    public final Sigma3Proof sigma;
    public final Sigma4Proof omega;

    public PFRStruct(CipherText ci_prime, BigInteger N, Sigma3Proof sigma) {
        this.ci_prime = ci_prime;
        this.n = N;
        this.sigma = sigma;
        this.omega = null;
    }

    public PFRStruct(CipherText ci_prime, BigInteger N, Sigma3Proof sigma, Sigma4Proof omega) {

        this.ci_prime = ci_prime;
        this.n = N;
        this.sigma = sigma;
        this.omega = omega;
    }
}
