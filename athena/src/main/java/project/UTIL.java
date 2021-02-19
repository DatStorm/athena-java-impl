package project;

import project.dao.sigma1.CoinFlipInfo;
import project.elgamal.GroupDescription;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Random;

public class UTIL {


    /**
     * Converts a list of BigInteger elements into a long concatenated byte array.
     * @param list to convert
     * @return byt[] of all elements in the list.
     * @throws IOException
     */
    public static byte[] ARRAYLIST_TO_BYTE_ARRAY(ArrayList<BigInteger> list) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        for (BigInteger el : list ) {
            stream.write(el.toByteArray());
        }
        return stream.toByteArray();
    }

    // Generate random element in range [1,p[
    public static BigInteger getRandomElement(BigInteger p, Random random) {
        return getRandomElement(BigInteger.ZERO, p, random);
    }

    // Generate random element in range [from, to[
    public static BigInteger getRandomElement(BigInteger from, BigInteger to, Random random) {
        boolean gIsInAllowedRange;
        BigInteger g = null;
        do {
            // Sample random number g between 0 and 2^{numbits} -1
            g = new BigInteger(to.bitLength(), random);

            //Check range
            boolean gIsGreaterEqualThanFrom = g.compareTo(from) >= 0;
            boolean gIsLesserThanTo = g.compareTo(to) == -1;
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

    public static void CompareElGamalGroup(GroupDescription a, GroupDescription b) {

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
         */

        double log_e_value = Math.log(value.doubleValue());
        double log_e_base = Math.log(base.doubleValue());
//        System.out.println("DOUBLE_V: " + log_e_value);
//        System.out.println("DOUBLE_B: " + log_e_base);


        return log_e_value / log_e_base;
    }
}
