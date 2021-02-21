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

    public CipherText multiply(CipherText c, BigInteger q) {

        BigInteger _c1 = this.c1.multiply(c.c1).mod(q);
        BigInteger _c2 = this.c2.multiply(c.c2).mod(q);

        return new CipherText(_c1,_c2);
    }


    public boolean compareTo(CipherText c) {
        boolean _b_c1 = this.c1.compareTo(c.c1) == 0;
        boolean _b_c2 = this.c2.compareTo(c.c2) == 0;

        if (!_b_c1) {
            System.out.println("CipherText.compareTo._b_c1 == false:");
            System.out.println("CipherText.compareTo.this.c1: \t\t" + this.c1);
            System.out.println("CipherText.compareTo.c.c1: \t\t\t" + c.c1);
        }
        if (!_b_c2) {
            System.out.println("CipherText.compareTo._b_c2 == false:");
            System.out.println("CipherText.compareTo.this.c2: \t\t" + this.c2);
            System.out.println("CipherText.compareTo.c.c2: \t\t\t" + c.c2);
        }

        return _b_c1 && _b_c2;
    }
}