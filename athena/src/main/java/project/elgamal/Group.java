package project.elgamal;

import project.UTIL;

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
        this.g = g;
        this.q = q;
        this.p = p;
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

    public BigInteger getG() {
        if (g == null){
            throw new RuntimeException("g has not been initialised");
        }
        return g;
    }

    public BigInteger newGenerator(Random random) {
        BigInteger i = UTIL.getRandomElement(q, random);
        BigInteger generator = g.modPow(i, p);

        assert generator.modPow(q, p).equals(BigInteger.ONE);

        return generator;
    }

    public List<BigInteger> newGenerators(int n, Random random) {
        ArrayList<BigInteger> generators = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            generators.add(newGenerator(random));
        }
        
        return generators;
    }



    @Override
    public String toString() {
        return "Group={'g': " + this.g + ",\n 'q': " + this.q + ",\n 'p': " + this.p + "\n}";
    }
}