package cs.au.athena.elgamal;

import cs.au.athena.UTIL;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

// Used for sending the ElGamal description over network
public class Group {
    public final BigInteger q;
    public final BigInteger p;
    public final BigInteger g;

    public Group(BigInteger p, BigInteger q, BigInteger g) {
        if (p == null || q == null || g == null){
            throw new IllegalArgumentException("Null is not allowed");
        }

        this.g = g;
        this.q = q;
        this.p = p;
    }

    public BigInteger getQ() {
        if (p == null){
            throw new IllegalArgumentException("Null is not allowed");
        }
        return q;
    }

    public BigInteger getP() {
        if (q == null ){
            throw new IllegalArgumentException("Null is not allowed");
        }
        return p;
    }

    public BigInteger getG() {
        if (g == null){
            throw new IllegalArgumentException("Null is not allowed");
        }
        return g;
    }

    // Generates a multiplicative subgroup of order q, where p,q are primes and p=2q+1
    public static Group generateGroup(int bitLength, Random random) {
        // SECURE == 2048
        BigInteger p, q, g;
        do {
            p = BigInteger.probablePrime(bitLength + 1, random); // p=2q+1
            q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO); // q = (p-1)/2


            // TODO: FIXME: this might lead to long execution time HOW CAN WE ADDRESS THIS
        } while (!q.isProbablePrime(bitLength)); // call returns true the probability that this BigInteger is prime exceeds (1 - 1/2^{certainty})

        g = UTIL.getRandomElement(BigInteger.TWO, p, random).modPow(BigInteger.TWO, p);


        if (p.bitLength() <= bitLength) {
            throw new RuntimeException("P, with bitLength " + p.bitLength() + ", is too small to encrypt numbers with bitlength " + bitLength);
        }

        assert g.modPow(q, p).equals(BigInteger.ONE) : "ElGamal group defined wrong, i.e. q definition is no good";


        return new Group(p, q, g);
    }

    public BigInteger newGenerator(Random random) {
        BigInteger i = UTIL.getRandomElement(q, random);
        BigInteger generator = g.modPow(i, p);
        assert generator.modPow(q, p).equals(BigInteger.ONE) : "(g^i)^q mod p != 1";

        return generator;
    }

    public List<BigInteger> newGenerators(int n, Random random) {
        assert BigInteger.valueOf(n).compareTo(q) < 0 : "n should be less then q";
        ArrayList<BigInteger> generators = new ArrayList<>(n);
        
        do {
            BigInteger newGen = newGenerator(random);
            if (! generators.contains(newGen)) {
                generators.add(newGen);
            }
        } while (generators.size() != n);
        return generators;
    }



    @Override
    public String toString() {
        return "Group={'g': " + this.g + ",\n 'q': " + this.q + ",\n 'p': " + this.p + "\n}";
    }
}