package project.dao;

import project.elgamal.ElGamalSK;

import java.math.BigInteger;

public class SK_R {
    private final ElGamalSK sk;
    private final Randomness r;

    public SK_R(ElGamalSK sk, Randomness r) {
        this.sk = sk;
        this.r = r;
    }

    public Randomness getR() {
        return this.r;
    }

    public ElGamalSK getElgamalSK() {
        return this.sk;
    }
}
