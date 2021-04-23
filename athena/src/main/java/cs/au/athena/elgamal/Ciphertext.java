package cs.au.athena.elgamal;

import java.math.BigInteger;
import java.util.Objects;

public class Ciphertext {
    public BigInteger c1;
    public BigInteger c2;

    public static Ciphertext ONE() {
        return new Ciphertext(BigInteger.ONE, BigInteger.ONE);
    }

    public Ciphertext(BigInteger c1, BigInteger c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    public Ciphertext modPow(BigInteger x, BigInteger p) {
        BigInteger c1 = this.c1.modPow(x, p);
        BigInteger c2 = this.c2.modPow(x, p);
        return new Ciphertext(c1, c2);
    }
    
    @Override
    public String toString() {
        return "\n\tCiphertext={'c1': " + this.c1 + ", 'c2':" + this.c2 + "}\n";
    }

    public String toFormattedString() {
        return "Ciphertext={\n\t\t'c1': " + this.c1 + ",\n \t\t'c2': " + this.c2 + "}\n";
    }

    public String toOneLineString() {
        return "Ciphertext={\t'c1': " + this.c1 + ",\t'c2': " + this.c2 + "}";
    }

    public Ciphertext multiply(Ciphertext c, BigInteger p) {
        if (p == null || c == null) {
            throw new IllegalArgumentException("Ciphertext.multiply: Missing group p ");
        }
        BigInteger _c1 = this.c1.multiply(c.c1).mod(p);
        BigInteger _c2 = this.c2.multiply(c.c2).mod(p);

        return new Ciphertext(_c1, _c2);
    }
    

    public Ciphertext modInverse(BigInteger p) {
        BigInteger _c1 = this.c1.modInverse(p);
        BigInteger _c2 = this.c2.modInverse(p);

        return new Ciphertext(_c1, _c2);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Ciphertext that = (Ciphertext) o;
        return Objects.equals(c1, that.c1) && Objects.equals(c2, that.c2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(c1, c2);
    }


    public String toShortString() {
        return "C={'c1': " + this.c1.toString().substring(0,5) + ", 'c2':" + this.c2.toString().substring(0,5) + "}";
    }
}