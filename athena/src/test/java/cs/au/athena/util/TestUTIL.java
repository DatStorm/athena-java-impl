package cs.au.athena.util;


import cs.au.athena.CONSTANTS;
import cs.au.athena.UTIL;
import cs.au.athena.dao.athena.ElectoralRoll;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.util.*;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

@RunWith(JUnitPlatform.class)
@Tag("TestsUTIL")
@DisplayName("Test cs.au.cs.au.athena.athena.UTIL")
public class TestUTIL {


    @Test
    void TestTablePrintPermutation() {
        BigInteger p = CONSTANTS.ELGAMAL_CURRENT.ELGAMAL_P;
        BigInteger q = CONSTANTS.ELGAMAL_CURRENT.ELGAMAL_Q;
        BigInteger g = CONSTANTS.ELGAMAL_CURRENT.ELGAMAL_G;
        Map<BigInteger, Integer> map = new HashMap<>();

        map.put(p, 1);
        map.put(q, 2);
        map.put(g, 3);
        map.put(p, 4);

        System.out.println(UTIL.lookupTableToString(map));

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
        Assertions.assertArrayEquals(objects.toArray(), result.toArray(), msg);
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
    @Test
    void TestProb() {
        List<BigInteger> nonces = new ArrayList<>();

        BigInteger q = CONSTANTS.ELGAMAL_32_BITS.ELGAMAL_Q;
        int n = q.bitLength() - 1;
        BigInteger endRange = BigInteger.TWO.modPow(BigInteger.valueOf(n), q).subtract(BigInteger.ONE); // [0; 2^n-1]
        BigInteger cur = BigInteger.ONE;

        int i = 0;

        do{
            nonces.add(cur);
            cur = UTIL.getRandomElement(BigInteger.ZERO, endRange, new Random());
            i++;

        }while( !nonces.contains(cur));

        System.out.println("cur:" + cur);
        System.out.println("iterations it took to produce a nonce all ready used:" + i);
        MatcherAssert.assertThat("", true, is(true));
    }







}
