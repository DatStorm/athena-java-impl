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
        this.coefficients = coefficients;
        this.group = group;
    }

    public List<BigInteger> getCoefficients() {
        return this.coefficients;
    }

    // Returns a random polynomial of degree @Param polyDegree, where P(0)=secret
    public static Polynomial newRandom(int polynomialDegree, Group group, Random random) {
        // Compute coefficients
        List<BigInteger> coefficients = new ArrayList<>();

        // The coefficients are random
        for (int i = 0; i <= polynomialDegree; i++) { // k + 1 coef
            coefficients.add(UTIL.getRandomElement(group.q, random));
        }

        // Return polynomial
        return new Polynomial(coefficients, group);
    }

    public BigInteger eval(int x) {
        BigInteger result = BigInteger.ZERO;

        for (int i = 0; i < coefficients.size(); i++) {
            BigInteger a = coefficients.get(i);
            BigInteger power = BigInteger.valueOf(x).pow(i).mod(group.q);

            // compute a_i * x^i (mod p)
            BigInteger big = a.multiply(power).mod(group.q);
            result = result.add(big).mod(group.q);
        }

        return result;
    }


    // Returns g^P(X)
    public List<BigInteger> getCommitments() {
        // [0: 1943345851, 1:3634149401, 2:1863252840]
        int size = coefficients.size();
        List<BigInteger> commitments = new ArrayList<>();

        for (int i = 0; i < size; i++){
            BigInteger coefficient = coefficients.get(i);
            BigInteger commitment = group.g.modPow(coefficient, group.p);
            commitments.add(commitment);
        }
        return commitments;
    }

    public  BigInteger getPointCommitment(int index) {
        return getPointCommitment(index, getCommitments(), group);
    }

    public static BigInteger getPointCommitment(int index, List<BigInteger> polynomialCommitments, Group group) {

        int size = polynomialCommitments.size();
        // P(X) = a0 + a1*x^1 + ... + ak * x^k
        // Så k+1 coefficienter

        BigInteger commitment = BigInteger.ONE;
        for(int ell = 0; ell < size; ell++) { // 0, 1, 2
            BigInteger jPowEll = BigInteger.valueOf(index).modPow(BigInteger.valueOf(ell), group.q);
            BigInteger coefficientCommitment = polynomialCommitments.get(ell);
            commitment = commitment.multiply(coefficientCommitment.modPow(jPowEll, group.p)).mod(group.p);
        }

        return commitment;
    }

    public static BigInteger getLambda(int x, int i, List<Integer> S) {
        BigInteger prod = BigInteger.ONE;
        BigInteger xBigInt = BigInteger.valueOf(x);
        BigInteger iBigInt = BigInteger.valueOf(i);

        for(int j : S) {
            BigInteger jBigInt = BigInteger.valueOf(j);
            if (iBigInt.equals(jBigInt)) {
                continue;
            }
            // j-x / j-i
            BigInteger j_sub_x = jBigInt.subtract(xBigInt);
            BigInteger j_sub_i = jBigInt.subtract(iBigInt);
            prod = j_sub_x.divide(j_sub_i);
        }
        return prod;
    }
}
