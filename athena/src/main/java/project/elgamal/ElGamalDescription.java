package project.elgamal;

import java.math.BigInteger;

// Used for sending the ElGamal description over network
public class ElGamalDescription {
    int bitLength;
    BigInteger q;
    BigInteger p;
    BigInteger g;

    ElGamalDescription(int bitLength, BigInteger p, BigInteger q, BigInteger g) {
        this.bitLength = bitLength;
        this.q = q;
        this.p = p;
        this.g = g;
    }
}