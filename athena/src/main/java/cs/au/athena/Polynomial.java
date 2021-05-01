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


    /**
     * P(0)=secret
     *
     * @param k      polynomial degree => Makes k+1 coefficients
     * @param group  Elgamal group
     * @param random random
     * @return a new random polynomial
     */
    public static Polynomial newRandom(int k, Group group, Random random) {
        // Compute coefficients
        List<BigInteger> coefficients = new ArrayList<>();

        // The coefficients are random
        for (int i = 0; i <= k; i++) { // k + 1 coef
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
        List<BigInteger> commitments = new ArrayList<>();

        for (BigInteger coefficient : this.coefficients) {
            BigInteger commitment = this.group.g.modPow(coefficient, this.group.p);
            commitments.add(commitment);
        }
        return commitments;
    }

    public BigInteger getPointCommitment(int index) {
        return getPointCommitment(index, getCommitments(), this.group);
    }

    public static BigInteger getPointCommitment(int index, List<BigInteger> polynomialCommitments, Group group) {
        int size = polynomialCommitments.size();
        // P(X) = a0 + a1*x^1 + ... + ak * x^k
        // Så k+1 coefficienter

        BigInteger commitment = BigInteger.ONE;
        for (int ell = 0; ell < size; ell++) { // 0, 1, 2
            BigInteger jPowEll = BigInteger.valueOf(index).modPow(BigInteger.valueOf(ell), group.q);
            BigInteger coefficientCommitment = polynomialCommitments.get(ell);
            commitment = commitment.multiply(coefficientCommitment.modPow(jPowEll, group.p)).mod(group.p);
        }

        return commitment;
    }

    public static BigInteger getLambda(int x, int i, List<Integer> S, Group group) {
        BigInteger prod = BigInteger.ONE;
        BigInteger xBigInt = BigInteger.valueOf(x);
        BigInteger iBigInt = BigInteger.valueOf(i);

        for (int j : S) {
            if (i == j) {
                continue;
            }
            BigInteger jBigInt = BigInteger.valueOf(j);
            // j-x / j-i
            BigInteger j_sub_x = jBigInt.subtract(xBigInt).mod(group.q).add(group.q).mod(group.q);
            BigInteger j_sub_i = jBigInt.subtract(iBigInt).mod(group.q).add(group.q).mod(group.q);
            BigInteger divide = j_sub_x.multiply(j_sub_i.modInverse(group.q)).mod(group.q).add(group.q).mod(group.q);
            prod = prod.multiply(divide).mod(group.q); // Properly not needed to modulo as the indices are much smaller than q.
        }
        return prod;
    }

    public int size() {
        return this.coefficients.size();
    }

    public Polynomial add(Polynomial p) {
        assert this.size() == p.size();

        List<BigInteger> coefficients = new ArrayList<>();
        for (int i = 0; i < this.size(); i++) {
            BigInteger add = this.coefficients.get(i).add(p.coefficients.get(i)).mod(group.q);
            coefficients.add(add);
        }


        return new Polynomial(coefficients, group);
    }


    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();

        s.append("P(X)= ");

        int ell = coefficients.size();
        for (int i = 0; i < ell; i++) {
            BigInteger coef = coefficients.get(i);
            s.append("x_").append(i).append("*").append(coef);
            if (i < ell - 1) {
                s.append(" + ");
            }
        }

        return s.toString();
    }
}
