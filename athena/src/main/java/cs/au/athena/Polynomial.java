package cs.au.athena;

import java.math.BigInteger;
import java.util.List;
import java.util.ArrayList;
import java.util.Random;
import cs.au.athena.elgamal.Group;

// P(X) = a_0 + a_1*x^1 + ... + a_k x^k
public class Polynomial {
    List<BigInteger> coefficients;
    Group group;

    public Polynomial(Group group) {
        this.coefficients = new ArrayList<>();
        this.group = group;
    }

    public Polynomial(List<BigInteger> coefficients, Group group) {
        this.coefficients = coefficients;
        this.group = group;
    }

    // Returns a random polynomial of degree @Param polyDegree, where P(0)=secret
    public static Polynomial newRandom(int polynomialDegree, Group group, Random random) {
        // Compute coefficients
        List<BigInteger> coefficients = new ArrayList<>();

        // The coefficiientsare random
        for (int i = 0; i < polynomialDegree; i++) {
            coefficients.add(UTIL.getRandomElement(group.q, random));
        }

        // Return polynomial
        return new Polynomial(coefficients, group);
    }

    public BigInteger get(int x) {
        BigInteger result = BigInteger.ZERO;

        for (int i = 0; i < coefficients.size(); i++) {
            // compute a_i * x^i (mod p)
            BigInteger power = BigInteger.valueOf((long) Math.pow(x, i));
            BigInteger big = coefficients.get(i).multiply(power).mod(group.p);

            result.add(big).mod(group.p);
        }

        return result;
    }


    // Returns g^P(X)
    public List<BigInteger> getCommitmentOfPolynomialCoefficients() {
        List<BigInteger> commitments = new ArrayList<>();

        for (BigInteger coefficient : this.coefficients){
            BigInteger commitment = this.group.g.modPow(coefficient, group.p);
            commitments.add(commitment);
        }

        return commitments;
    }


}
