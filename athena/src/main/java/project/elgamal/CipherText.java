package project.elgamal;

import java.math.BigInteger;
import java.util.Objects;

public class CipherText {
    public BigInteger c1;
    public BigInteger c2;

    public CipherText(BigInteger c1, BigInteger c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    public CipherText modPow(BigInteger x, BigInteger p) {
        BigInteger c1 = this.c1.modPow(x, p);
        BigInteger c2 = this.c2.modPow(x, p);
        return new CipherText(c1, c2);
    }

    @Override
    public String toString() {
        return "\n\tCiphertext={'c1': " + this.c1 + ", 'c2':" + this.c2 + "}\n";
    }


    public CipherText multiply(CipherText c, BigInteger p) {
        // TODO: Enforce mod p. User of function should not decide. Maybee include public key or group in fields?
        if (p == null) {
            throw new IllegalArgumentException("Missing group p ");
        }
        BigInteger _c1 = this.c1.multiply(c.c1).mod(p);
        BigInteger _c2 = this.c2.multiply(c.c2).mod(p);

        return new CipherText(_c1, _c2);
    }
    

    public CipherText modInverse(BigInteger p) {
        BigInteger _c1 = this.c1.modInverse(p);
        BigInteger _c2 = this.c2.modInverse(p);

        return new CipherText(_c1, _c2);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CipherText that = (CipherText) o;
        return Objects.equals(c1, that.c1) && Objects.equals(c2, that.c2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(c1, c2);
    }
}