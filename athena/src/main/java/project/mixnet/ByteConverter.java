package project.mixnet;

import org.apache.commons.lang3.ArrayUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

public class ByteConverter {



    /**
     * @param bytes little endian
     */
    public static List<Boolean> valueOf(byte[] bytes, int n_bits) {
        List<Boolean> result = new ArrayList<>(n_bits);
        BitSet bitSet = BitSet.valueOf(bytes);

        for(int i = 0; i < n_bits; i++) {
            result.add(i, bitSet.get(i));
        }

        return result;
    }

    public static List<Boolean> valueOf(BigInteger value, int nbits) {
        if (value.signum() != 1) {
            throw new RuntimeException("value must be positive");
        }

        // Get bytes
        byte[] bytes = value.toByteArray(); // Big endian
        ArrayUtils.reverse(bytes); // To little endian

        // Ensure the length is correct. Truncates if too long. Appends 0 bytes if too short.
        int nbytes = nbits / 8;
        bytes = Arrays.copyOfRange(bytes, 0, nbytes);

        return ByteConverter.valueOf(bytes, nbits);
    }


}
