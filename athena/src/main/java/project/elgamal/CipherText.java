package project.elgamal;

import java.math.BigInteger;

public class CipherText {
    public BigInteger c1;
    public BigInteger c2;

    public CipherText(BigInteger c1, BigInteger c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    public CipherText modPow(BigInteger x, BigInteger p) {
        return new CipherText(c1.modPow(x,p), c2.modPow(x,p));
    }

    @Override
    public String toString() {
        return "\n\tCiphertext={'c1': " + this.c1 + ", 'c2':" +this.c2 + "}\n";
    }
}