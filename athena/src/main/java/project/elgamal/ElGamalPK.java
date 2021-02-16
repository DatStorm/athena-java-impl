package project.elgamal;

import java.math.BigInteger;

public class ElGamalPK {
    private BigInteger g;
    private BigInteger h;

    public ElGamalPK(BigInteger g, BigInteger h) {
        this.g = g;
        this.h = h;
    }
}
