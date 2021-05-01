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