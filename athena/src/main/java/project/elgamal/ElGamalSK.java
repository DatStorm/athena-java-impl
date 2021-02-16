package project.elgamal;

import java.math.BigInteger;

public class ElGamalSK {
    private BigInteger sk;

    public ElGamalSK(BigInteger sk) {
        this.sk = sk;
    }

    public BigInteger getSK() {
        return this.sk;
    }
}
