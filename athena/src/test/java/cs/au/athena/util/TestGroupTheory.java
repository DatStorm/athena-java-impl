package cs.au.athena.util;


import cs.au.athena.CONSTANTS;
import cs.au.athena.Polynomial;
import cs.au.athena.UTIL;
import cs.au.athena.elgamal.Group;
import cs.au.athena.elgamal.GroupTheory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;

@RunWith(JUnitPlatform.class)
@Tag("TestGroupTheory")
@DisplayName("Test Group Theory")
public class TestGroupTheory {


    @Test
    void TestGroupForwardBack() {
        Random rand = new Random();
        Group group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        BigInteger q = group.q;
        BigInteger randEl = UTIL.getRandomElement(q, rand);


        // 10 = g(f(10))
        BigInteger subshareElement = GroupTheory.fromZqToG(randEl, group);
        BigInteger subShareFromTallier_j = GroupTheory.fromGToZq(subshareElement, group);

        MatcherAssert.assertThat("Should be the same", subShareFromTallier_j, is(randEl));
    }


    @Test
    void TestExperimentGroupExponentiations() {
        int experiments;
//        experiments = 10000;
        experiments = 20000;
//        experiments = 50000;

        Group big_group = CONSTANTS.ELGAMAL_2048_BITS.GROUP; // Big group: |q| = 2048 bits
        Group small_group = CONSTANTS.ELGAMAL__DIFFIE_HELLMAN_GROUP__.GROUP; // small group: |q| = 256 bits

        Group group = big_group;

        /** *********/
        BigInteger elem = UTIL.getRandomElement(group.q, new Random(CONSTANTS.RANDOM_SEED));

        long startTime = System.nanoTime();

        BigInteger p = group.p;
        BigInteger q = group.q;
        BigInteger g = group.g;

        // Do many exponentiations
        for (int i = 0; i < experiments; i++) {

            // g^el mod p , el \in q
            BigInteger tmp = g.modPow(elem, p);
        }



        long endTime = System.nanoTime();
        /** *********/

        System.out.println(String.format("experiments: %d", experiments));
        UTIL.printNarrowEvalMetrics("Big group: ", startTime, endTime);

    }

}
