package cs.au.athena.util;


import cs.au.athena.CONSTANTS;
import cs.au.athena.GENERATOR;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(JUnitPlatform.class)
@Tag("TestGenerator")
@DisplayName("Test Generator")
public class TestGenerator {


    @Test
    void TestGeneratorNonce() {


        Random random = new Random(CONSTANTS.RANDOM_SEED);
        BigInteger q = BigInteger.TEN;
        BigInteger from = BigInteger.ZERO;
        BigInteger n1 = GENERATOR.generateUniqueNonce(from,q, random);
        System.out.println(n1);


        for (int i = 0; i < 9; i++) {
            BigInteger n2 = GENERATOR.generateUniqueNonce(from,q, random);
            System.out.println(i + " : "+ n2);
            assertThat("fae", n2, not(is(n1)));

        }

    }
}
