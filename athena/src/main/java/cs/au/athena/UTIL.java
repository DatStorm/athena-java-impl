package cs.au.athena;

import com.google.common.collect.Streams;
import cs.au.athena.athena.AthenaTally;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.sigma1.CoinFlipInfo;
import cs.au.athena.elgamal.Ciphertext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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
                System.out.println("cs.au.cs.au.athena.athena.UTIL.ARRAYLIST_TO_BYTE_ARRAY------------------> ERROR!!! ");
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
            System.out.println("cs.au.cs.au.athena.athena.UTIL.getRandomElement::\tWarning: getRandomElement probably does not work for negative values.");
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
        Collections.shuffle(range, random);
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

    public static void printEvalMetrics(String TAG, long startTime, long endTime){
        long timeElapsed = endTime - startTime;
        System.out.println(TAG + "Execution time in seconds : \t\t\t" + nanosecToSec(timeElapsed)); // HERE..
        System.out.println(TAG + "Execution time in minutes : \t\t\t" + nanosecToMin(timeElapsed)); // HERE..
    }

    public static void printNarrowEvalMetrics(String TAG, long startTime, long endTime){
        long timeElapsed = endTime - startTime;
        System.out.printf("%s [ms=%d]%n", TAG ,nanosecToMilli(timeElapsed));
    }

    private static long nanosecToMilli(long timeElapsed) {
        return TimeUnit.MILLISECONDS.convert(timeElapsed, TimeUnit.NANOSECONDS);
    }

    private static long nanosecToSec(long timeElapsed) {
        return TimeUnit.SECONDS.convert(timeElapsed, TimeUnit.NANOSECONDS);
    }

    private static long nanosecToMin(long nanoSeconds) {
        // https://stackoverflow.com/a/924221
        long res = TimeUnit.MINUTES.convert(nanoSeconds, TimeUnit.NANOSECONDS);
//        long res_mark = nanoSeconds / (1000 * 1000 * 60);
//        res_mark = res_mark / 1000;
//
//        System.out.println("RES     : " + res);
//        System.out.println("RES MARK: " + res_mark);
        return res;
    }

    public static <T> String prettyPrintList(List<T> ballots ) {
        StringBuilder s = new StringBuilder();
        s.append("\n");
        s.append("---".repeat(20));
        s.append("\n");
        s.append("|\ti\t|\tval                                            |");
        s.append("\n");

        for (int i = 0; i < ballots.size(); i++) {
            s.append("|\t");
            s.append(i);
            s.append("\t|\t");
            s.append(ballots.get(i));
            s.append("\n");
        }
        s.append("---".repeat(20));
        s.append("\n");
        return s.toString();
    }


    public static String lookupTableToString(Map<BigInteger,Integer> map ) {

        Map<BigInteger, Integer> sorted = map
                .entrySet()
                .stream()
                .sorted(Map.Entry.comparingByValue())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (e1, e2) -> e1, LinkedHashMap::new));

        StringBuilder s = new StringBuilder();
        s.append("\n");
        s.append("---".repeat(20));

        s.append("\n");
        s.append("|\tv\t|\tg^v                                            |");
        s.append("\n");

        for(Map.Entry<BigInteger, Integer> entry : sorted.entrySet() ){
            s.append("|\t");
            s.append(entry.getValue());
            s.append("\t|\t");
            s.append(entry.getKey());
            s.append("\n");
        }
        s.append("---".repeat(20));
        s.append("\n");
        return s.toString();
    }

    public static String cipherTextListToString(List<Ciphertext> ciphertextList) {
        StringBuilder s = new StringBuilder();
        s.append("\n");
        s.append("---".repeat(20));
        s.append("\n");
        s.append("|\ti\t|\tval                                            |");
        s.append("\n");

        for (int i = 0; i < ciphertextList.size(); i++) {
            s.append("|\t");
            s.append(i);
            s.append("\t|\t");
            s.append(ciphertextList.get(i).toListString());
            s.append("\n");
        }
        s.append("---".repeat(20));
        s.append("\n");
        return s.toString();
    }

    public static String prettyPrintTallyResult(Map<Integer, Integer> map) {
        StringBuilder s = new StringBuilder();
        s.append("\n");
        s.append("---".repeat(20));
        s.append("\n");
        s.append("|\t\tCandidate\t\t\t|\t\t\t  Votes\t\t\t   |");
        s.append("\n");

        for(Map.Entry<Integer, Integer> entry : map.entrySet() ){
            s.append("|\t\t\t");
            s.append(entry.getKey());
            s.append("\t\t\t\t|\t\t\t\t");
            s.append(entry.getValue());
            s.append("\t\t\t   |");
            s.append("\n");
        }
        s.append("---".repeat(20));
        s.append("\n");
//        s.append("\n");
//        s.append("\n");

        int totalCandidates = map.keySet().size();
        int totalVotes = map.values().stream().reduce(0, Integer::sum);
        s.append("**** ");

        s.append("\t").append(totalCandidates).append(" total candidates and all total votes were ").append(totalVotes);
        s.append("\t****");
        s.append("\n");


//        s.append("***".repeat(20));
//        s.append("---".repeat(20));

        int maxCandidate = Collections.max(map.entrySet(), Comparator.comparingInt(Map.Entry::getValue)).getKey();
        int maxVotes = map.get(maxCandidate);
        s.append("**** ");
        s.append("\t\t\tCandidate ").append(maxCandidate).append(" won with ").append(maxVotes).append(" votes. ");
        s.append("\t\t\t****");
        s.append("\n");
        s.append("***".repeat(20));
//        s.append("---".repeat(20));

        s.append("\n");




        return s.toString();
    }
}
