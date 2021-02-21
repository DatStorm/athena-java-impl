package util;


import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.UTIL;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@Tag("TestsUTIL")
@DisplayName("Test UTIL")
public class TestUTIL {


    @Test
    void TestUTIL_log() {

        BigInteger _256 = BigInteger.valueOf(256);
        BigInteger _2 = BigInteger.valueOf(2);

        double res = UTIL.BigLog(_2, _256);
        assertEquals("value res= " + res, 8.0, res, 0.00001);
    }

    @Test
    void TestInversePermutation() {
        List<Integer> objects = UTIL.newPermutation(10, new Random(0));
        List<Integer> permutation = UTIL.newPermutation(10, new Random(1));
        List<Integer> inversePermutation = UTIL.inversePermutation(permutation);

        List<Integer> permutedObjects = UTIL.permute(objects, permutation);
        List<Integer> result = UTIL.permute(permutedObjects, inversePermutation);

        String msg = "A: " + Arrays.toString(objects.toArray()) + "\n B: " + Arrays.toString(result.toArray()) + "\n";
//        System.out.println(msg);
        assertArrayEquals(msg, objects.toArray(), result.toArray());


    }


}
