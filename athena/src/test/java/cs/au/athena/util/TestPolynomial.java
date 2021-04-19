package cs.au.athena.util;


import cs.au.athena.CONSTANTS;
import cs.au.athena.Polynomial;
import cs.au.athena.elgamal.Group;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.*;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;

@RunWith(JUnitPlatform.class)
@Tag("TestPolynomial")
@DisplayName("Test Polynomial")
public class TestPolynomial {
    static Random random;
    static Group group;

    @BeforeAll
    static void BeforeAll() {
        group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        random = new Random(0);
    }

    @Test
    public void TestPolynomialPointCommitments() {
        int k = 2;
        Group group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        Random random = new Random(1);

        // P(X) = 1 + 10x
        //Polynomial poly = new Polynomial(Arrays.asList(BigInteger.ONE, BigInteger.TEN), group);
        Polynomial poly = Polynomial.newRandom(k, group, random);
        List<BigInteger> commitments = poly.getCommitments();

        // Commitment to P(4)
        int x = 4;
        BigInteger bigy = poly.eval(x);

        BigInteger pointCommitment_a = Polynomial.getPointCommitment(x, commitments, group);
        BigInteger pointCommitment_b = group.g.modPow(bigy, group.p);

//        MatcherAssert.assertThat(pointCommitment_a.bitLength(), is(pointCommitment_b.bitLength()));

        MatcherAssert.assertThat(pointCommitment_a, is(pointCommitment_b));
    }

    @Test
    public void TestPolynomialCommitments() {
        int k = 20;
        Group group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        Random random = new Random(22);

        // P(X) = 1 + 2x
        Polynomial poly = Polynomial.newRandom(k, group, random);
        List<BigInteger> coefficients = poly.getCoefficients();
        List<BigInteger> committedCoefficients = poly.getCommitments();

        // Check that the commitments are valid for all coefficients.
        for(int i = 0; i <= k; i++) {
            BigInteger coefficient = coefficients.get(i);
            BigInteger committedCoefficient = committedCoefficients.get(i);

            MatcherAssert.assertThat(group.g.modPow(coefficient, group.p), is(committedCoefficient));
        }
    }

    @Test
    public void TestPolynomial() {
        int k = 2;
        Group group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        Random random = new Random(0);

        // P(X) = 1 + 2x
        Polynomial poly = new Polynomial(Arrays.asList(BigInteger.ONE, BigInteger.TWO), group);

        int x = 4;
        int y = 9; // 1 + 2*4 = 9

        MatcherAssert.assertThat(poly.eval(x), is(BigInteger.valueOf(y)));
    }

    @Test
    public void TestPolynomialPointCommitmentsSmall() {
        int k = 2;
        Group group = CONSTANTS.ELGAMAL_CURRENT.GROUP;

        // P(X) = 1 + 2x
        Polynomial poly = new Polynomial(Arrays.asList(BigInteger.TWO, BigInteger.ONE, BigInteger.TEN), group);
        List<BigInteger> commitments = poly.getCommitments();

        int x = random.nextInt(1000);
        BigInteger bigy = poly.eval(x);

        // Commitment to P(x)=y
        BigInteger pointCommitment_a = Polynomial.getPointCommitment(x, commitments, group);
        BigInteger pointCommitment_b = group.g.modPow(bigy, group.p);

        MatcherAssert.assertThat(pointCommitment_a, is(pointCommitment_b));
    }

}
