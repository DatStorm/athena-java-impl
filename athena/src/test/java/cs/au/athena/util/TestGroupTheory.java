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
}
