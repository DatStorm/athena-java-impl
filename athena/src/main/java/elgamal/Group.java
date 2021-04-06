package elgamal;

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
        }while (generators.size() != n);
        return generators;
    }



    @Override
    public String toString() {
        return "Group={'g': " + this.g + ",\n 'q': " + this.q + ",\n 'p': " + this.p + "\n}";
    }
}