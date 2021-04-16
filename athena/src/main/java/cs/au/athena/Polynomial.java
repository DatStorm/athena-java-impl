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

    public Polynomial(List<BigInteger> coefficients, Group group) {
        this.group = group;
    }

    // Returns a random polynomial of degree @Param polyDegree, where P(0)=secret
    public static Polynomial secretShare(BigInteger secret, int polynomialDegree, Group group, Random random) {
        // Compute coefficients
        List<BigInteger> coefficients = new ArrayList<>();

        // The first is the secret
        coefficients.add(secret);

        // The rest are random
        for (int i = 1; i < polynomialDegree; i++) {
            coefficients.add(UTIL.getRandomElement(group.q, random));
        }

        // Return polynomial
        return new Polynomial(coefficients, group);
    }

    public BigInteger get(BigInteger x) {
        BigInteger result = BigInteger.ZERO;

        for (int i = 0; i < coefficients.size(); i++) {
            // compute a_i * x^i (mod p)
            BigInteger big = coefficients.get(i).multiply(x.pow(i)).mod(group.p);
            result.add(big);
        }

        return null;
    }


}
