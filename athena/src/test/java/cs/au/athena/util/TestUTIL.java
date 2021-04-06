package cs.au.athena.util;


import cs.au.athena.UTIL;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.*;

@RunWith(JUnitPlatform.class)
@Tag("TestsUTIL")
@DisplayName("Test cs.au.cs.au.athena.athena.UTIL")
public class TestUTIL {


    @Test
    void TestUTIL_log() {

        BigInteger _256 = BigInteger.valueOf(256);
        BigInteger _2 = BigInteger.valueOf(2);

//        double res = cs.au.cs.au.athena.athena.UTIL.BigLog(_2, _256);
//        assertEquals("value res= " + res, 8.0, res, 0.00001);
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

    @Test
    void TestInversePermOfIdentity() {
        List<Integer> objects = UTIL.newPermutation(10, new Random(0));
        List<Integer> objects_perm = UTIL.permute(objects,objects);
        List<Integer> inversePermutation = UTIL.inversePermutation(objects);

        List<Integer> result = UTIL.permute(objects_perm, inversePermutation);
        assertArrayEquals(objects.toArray(), result.toArray());

        
    }

   @Test
    void TestInversePermOfIdentity2() {
        List<Integer> identity = new ArrayList<>(Arrays.asList(0, 1, 2, 3, 4, 5));
        List<Integer> inversePermutation = UTIL.inversePermutation(identity);
        assertArrayEquals(identity.toArray(), inversePermutation.toArray());

        List<Integer> identity2 = new ArrayList<>(Arrays.asList(0, 5, 1, 4, 3, 2));

        List<Integer> inversePermutation2 = UTIL.inversePermutation(identity2);

        List<Integer> obj = UTIL.permute(identity, identity2);
        obj = UTIL.permute(obj, inversePermutation2);

        assertArrayEquals(identity.toArray(), obj.toArray());
    }




    @Test
    void TestInversePerm() {
        List<Integer> objects = UTIL.newPermutation(10, new Random(0));

    }

    @Test
    void TestRange() {
        BigInteger start = BigInteger.valueOf(0);
        BigInteger end = BigInteger.valueOf(10);

        assertTrue(UTIL.BIGINT_IN_RANGE(start,end,BigInteger.valueOf(10)));
        assertTrue(UTIL.BIGINT_IN_RANGE(start,end,BigInteger.valueOf(0)));
        assertTrue(UTIL.BIGINT_IN_RANGE(start,end,BigInteger.valueOf(1)));

        assertFalse(UTIL.BIGINT_IN_RANGE(start,end,BigInteger.valueOf(-11)));
        assertFalse(UTIL.BIGINT_IN_RANGE(start,end,BigInteger.valueOf(-1)));
        assertFalse(UTIL.BIGINT_IN_RANGE(start,end,BigInteger.valueOf(11)));
        assertFalse(UTIL.BIGINT_IN_RANGE(start,end,BigInteger.valueOf(20)));

    }




}
