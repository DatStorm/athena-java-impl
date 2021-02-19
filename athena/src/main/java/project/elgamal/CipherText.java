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
        BigInteger _c1 = this.c1.modPow(x, p);
        BigInteger _c2 = this.c2.modPow(x, p);
//        System.out.println("x = " + x + ", p = " + p);
//        System.out.println("c1 = " + this.c1 + ", c2 = " + this.c2);
//        System.out.println("_c1 = " + _c1 + ", _c2 = " + _c2);
        return new CipherText(_c1, _c2);
    }

    @Override
    public String toString() {
        return "\n\tCiphertext={'c1': " + this.c1 + ", 'c2':" +this.c2 + "}\n";
    }
}