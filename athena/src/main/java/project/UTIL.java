package project;

import com.google.common.collect.Streams;
import project.dao.sigma1.CoinFlipInfo;
import project.elgamal.Group;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.Collections;

public class UTIL {


    /**
     * Converts a list of BigInteger elements into a long concatenated byte array.
     *
     * @param list to convert
     * @return byt[] of all elements in the list.
     * @throws IOException
     */
    public static byte[] ARRAYLIST_TO_BYTE_ARRAY(ArrayList<BigInteger> list)  {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        for (BigInteger el : list) {
            try {
                
                stream.write(el.toByteArray());
            } catch (IOException e) {
                
                e.printStackTrace();
                System.out.println("UTIL.ARRAYLIST_TO_BYTE_ARRAY------------------> ERROR!!! ");
            }
        }
        return stream.toByteArray();
    }

    // Generate @size random elements in range [1,p[
    public static List<BigInteger> getRandomElements(BigInteger endExclusive, int size, Random random) {
        List<BigInteger> elements = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            elements.add(getRandomElement(endExclusive, random));
        }
        return elements;
    }

    // Generate @param size random element in range [1,p[
    public static BigInteger getRandomElement(BigInteger endExclusive, Random random) {
        return getRandomElement(BigInteger.ZERO, endExclusive, random);
    }

    // Generate random element in range [from, to[
    public static BigInteger getRandomElement(BigInteger startInclusive, BigInteger endExclusive, Random random) {
        if(startInclusive.signum() == -1) {
            System.out.println("UTIL.getRandomElement::\tWarning: getRandomElement probably does not work for negative values.");
        }

        boolean gIsInAllowedRange;
        BigInteger g = null;
        do {
            // Sample random number g between 0 and 2^{numbits} - 1
            g = new BigInteger(endExclusive.bitLength(), random);

            //Check range
            boolean gIsGreaterEqualThanFrom = g.compareTo(startInclusive) >= 0;
            boolean gIsLesserThanTo = g.compareTo(endExclusive) == -1;
            gIsInAllowedRange = gIsGreaterEqualThanFrom && gIsLesserThanTo;
        } while (!gIsInAllowedRange);

        return g;
    }


    /**
     * https://www.geeksforgeeks.org/find-the-index-of-an-array-element-in-java/
     *
     * @param list   to search in
     * @param number to find
     * @return
     */
    public static int findFirstOne(ArrayList<CoinFlipInfo> list, int number) {

        // if array is Null
        if (list == null) {
            System.err.println("findMinIndex().list was null");
            return -1;
        }

        // find length of array
        int len = list.size();
        int i = 0;

        // traverse in the array
        while (i < len) {
            // get the bit value.
            int val = list.get(i).getBi() ? 1 : 0;

            // if the i-th element is number
            // then return the index
            if (val == number) {
                return i;
            } else {
                i++;
            }
        }
        System.out.println("Did not find the number in the list.... Returning -1");
        return -1;
    }

    /*
    public static void CompareElGamalGroup(Group a, Group b) {
        assert a.getP().compareTo(b.getP()) == 0 : "a.p != b.p";
        assert a.getQ().compareTo(b.getQ()) == 0 : "a.q != a.q";
        assert a.getG().compareTo(b.getG()) == 0 : "a.g != b.g";

    }

    public static double BigLog(BigInteger base, BigInteger value) {
        /*
         * log_alphabase alpha = n =?= n
         */
        // Use identity:
        // log_b(n) = log_e(n) / log_e(b)
        /* EXAMPLE: [find the base-2 logarithm of 256]
            Math.log(256) / Math.log(2)
            => 8.0
         /

        double log_e_value = Math.log(value.doubleValue());
        double log_e_base = Math.log(base.doubleValue());
//        System.out.println("DOUBLE_V: " + log_e_value);
//        System.out.println("DOUBLE_B: " + log_e_base);


        return log_e_value / log_e_base;
    }
    */

    public static boolean CompareLists(List<?> l1, List<?> l2) {
        // make a copy of the list so the original list is not changed, and remove() is supported
        ArrayList<?> cp = new ArrayList<>(l1);
        for (Object o : l2) {
            if (!cp.remove(o)) {
                return false;
            }
        }
        return cp.isEmpty();
    }


    // result = [obj_pi(0), obj_pi(1), ...]
    public static <T> List<T> permute(List<T> objects, List<Integer> permutation) {
        //pi [0,2,3,1,4].
        ArrayList<T> permutedObjects = new ArrayList<>();
        for (Integer j : permutation) {
            // Move object pi(i) to position i in the new list
            permutedObjects.add(objects.get(j));
        }
        return permutedObjects;
    }

    public static List<Integer> inversePermutation(List<Integer> permutation) {
        // Find the permutation that will undo pi.
        //(obj_pi(0), obj_pi(1),...)
        //
        int size = permutation.size();
        List<Integer> inversePermutation = new ArrayList<>(permutation);
        for(int i = 0; i < size; i++) {
            int j = permutation.get(i);

            // list is already filled
            inversePermutation.set(j, i);
        }

        return inversePermutation;
    }

    public static List<Integer> newPermutation(int size, Random random) {
        List<Integer> range = IntStream.range(0, size).boxed().collect(Collectors.toList());
        Collections.shuffle(range);
        return range;
    }

    public static List<Integer> composePermutation(List<Integer> pi1, List<Integer> pi2) {
        return permute(pi1, pi2);
    }


    // https://www.geeksforgeeks.org/biginteger-compareto-method-in-java/
    public static boolean BIGINT_IN_RANGE(BigInteger start, BigInteger end, BigInteger value) {
        // value \in [start,end]

        // start >= end
        if (start.compareTo(end) > 0) {
            System.out.println("Start range is higher or equal then end range");
        }
        // value <= end
        if (value.compareTo(end) > 0) {
            return false;

        // value >= start
        } else if (value.compareTo(start) <  0) {
            return false;
        }

        return true;
    }

  
    public static MessageDigest GET_HASH_FUNCTION() {
        MessageDigest sha3_256 = null;
        try {
            sha3_256 = MessageDigest.getInstance(CONSTANTS.ALGORITHM_SHA3_256);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return sha3_256;
    }

    public static BigInteger modPowSum(BigInteger base, List<BigInteger> exponents, BigInteger modolus) {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger exponent : exponents) {
            sum = sum.add(base.modPow(exponent, modolus));
            sum = sum.mod(modolus);
        }

        return sum;
    }

    // compute a^b for vectors a and b
    public static BigInteger exponentProductSequence(
            List<BigInteger> list_a,
            List<BigInteger> list_b,
            BigInteger order) {

        return Streams.zip(list_a.stream(), list_b.stream(),
                (bigInt_a, bigInt_b) -> bigInt_a.modPow(bigInt_b, order)
        )
                .reduce(BigInteger.ONE, BigInteger::multiply);
    }


    public static List<BigInteger> addLists(List<BigInteger> a, List<BigInteger> b, BigInteger order) {
        return Streams.zip(a.stream(), b.stream(), (_a, _b) -> _a.add(_b).mod(order))
        .collect(Collectors.toList());
    }

    public static List<BigInteger> subtractLists(List<BigInteger> a, List<BigInteger> b, BigInteger order) {
        return Streams.zip(a.stream(), b.stream(), (_a, _b) -> _a.subtract(_b).mod(order).add(order).mod(order))
        .collect(Collectors.toList());
    }


    // compute a^b for vectors a and b
    public static List<BigInteger> generateListExponentVectors(List<BigInteger> list_a, List<BigInteger> list_b, BigInteger order) {
        return Streams.zip(list_a.stream(), list_b.stream(), (bigInt_a, bigInt_b) -> bigInt_a.modPow(bigInt_b, order)).collect(Collectors.toList());
    }

    public static BigInteger dotProduct(List<BigInteger> l_vector, List<BigInteger> r_vector, BigInteger order) {
        assert l_vector.size() == r_vector.size() : "UTIL.dotProduct() => " + l_vector.size() + " != " + r_vector.size();
        
        return hadamardProduct(l_vector, r_vector, order).stream()
                .reduce(BigInteger.ZERO, BigInteger::add)
                .mod(order);
    }

    public static List<BigInteger> hadamardProduct(List<BigInteger> l_vector, List<BigInteger> r_vector, BigInteger order) {
        if (l_vector.size() != r_vector.size()) {
            throw new IllegalArgumentException("List sizes must match");
        }

        int n = l_vector.size();
        List<BigInteger> result = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            result.add(l_vector.get(i).multiply(r_vector.get(i)).mod(order));
        }

        return result;
    }


}
