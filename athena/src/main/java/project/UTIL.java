package project;

import project.dao.sigma1.CoinFlipInfo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
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
        boolean gIsInAllowedRange;
        BigInteger g = null;
        do {
            // Sample random number g between 1 and p
            g = new BigInteger(p.bitLength(), random);

            //Check range
            boolean gIsGreaterThatZero = g.compareTo(BigInteger.ZERO) == 1;
            boolean gIsLesserThanP = g.compareTo(p) == -1;
            gIsInAllowedRange = gIsGreaterThatZero && gIsLesserThanP;
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
}
