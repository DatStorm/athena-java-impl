package project.elgamal;

import java.math.BigInteger;

// Used for sending the ElGamal description over network
public class GroupDescription {
    BigInteger g;
    BigInteger q;
    BigInteger p;

    GroupDescription(BigInteger g, BigInteger p, BigInteger q) {
        this.g = g;
        this.q = q;
        this.p = p;
    }


    public BigInteger getG() {
        if (g == null){
            throw new RuntimeException("g has not been initialised");
        }
        return g;
    }

    public BigInteger getQ() {
        if (q == null){
            throw new RuntimeException("q has not been initialised");
        }
        return q;
    }

    public BigInteger getP() {
        if (p == null){
            throw new RuntimeException("p has not been initialised");
        }
        return p;
    }
}