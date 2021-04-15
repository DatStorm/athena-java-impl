package cs.au.athena.elgamal;

import com.google.common.primitives.Bytes;
import cs.au.athena.UTIL;
import org.junit.jupiter.api.*;
import cs.au.athena.factory.Factory;
import cs.au.athena.factory.MainFactory;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.*;
import static org.junit.Assert.assertArrayEquals;

@Tag("TestsCiphertexts")
@DisplayName("Test CipherTexts")
public class TestElgamalCiphertext {
    private Elgamal elgamal;
    private ElGamalPK pk;
    private ElGamalSK sk;


    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();

        elgamal = factory.getElgamal();
        pk = factory.getPK();
        sk = factory.getSK();

    }

    @Test
    void TestCipherTextAdd() {
        long a = 11000000;
        long b = 3000099;
        long c = a * b;

        BigInteger big_a = BigInteger.valueOf(a);
        BigInteger big_b = BigInteger.valueOf(b);

        Ciphertext c_1 = elgamal.exponentialEncrypt(big_a, pk);
        Ciphertext c_2 = elgamal.exponentialEncrypt(big_b, pk);

        BigInteger p = pk.getGroup().p;
        BigInteger q = pk.getGroup().q;
        BigInteger g = pk.getGroup().g;
        Ciphertext cAdd = c_1.multiply(c_2, p);
        BigInteger dec_mult = elgamal.decrypt(cAdd, sk);
        BigInteger g_c = g.modPow(big_a.add(big_b).mod(q), p);
        assertEquals("Should be " + "a=" + a + ", b=" + b + ", a*b=c=" + dec_mult, 0, dec_mult.compareTo(g_c));
    }

    @Test
    @Disabled
    void TestCipherTextToByteArray() {
        long a = 10;
        long b = 100;

        BigInteger big_a = BigInteger.valueOf(a);
        BigInteger big_b = BigInteger.valueOf(b);

        Ciphertext c1 = elgamal.exponentialEncrypt(big_a, pk);
        Ciphertext c2 = elgamal.exponentialEncrypt(big_b, pk);

        byte[] c1_c1 = c1.c1.toByteArray(); // [0, -100, -87, 127, 84, -89, -15, 44, -52, 93, 106, -29, 2, -5, 66, 6, 94]
        byte[] c1_c2 = c1.c2.toByteArray(); // [81, 28, -73, -25, -117, -25, 88, 74, 27, 30, -109, -44, 118, 118, -66, 87]

//        System.out.println("c1_c1: " + Arrays.toString(c1_c1));

        byte[] c1_concat = Bytes.concat(c1_c1, c1_c2);
//        assertArrayEquals(new byte[]{0, -100, -87, 127, 84, -89, -15, 44, -52, 93, 106, -29, 2, -5, 66, 6, 94, 81, 28, -73, -25, -117, -25, 88, 74, 27, 30, -109, -44, 118, 118, -66, 87}, c1_concat);

        BigInteger c1_big = new BigInteger(c1_concat);
//        assertArrayEquals(new byte[]{0, -100, -87, 127, 84, -89, -15, 44, -52, 93, 106, -29, 2, -5, 66, 6, 94, 81, 28, -73, -25, -117, -25, 88, 74, 27, 30, -109, -44, 118, 118, -66, 87}, c1_big.toByteArray());

        byte[] c2_c1 = c2.c1.toByteArray(); // [1, 72, 105, -92, 1, 84, -74, 54, 2, 61, -54, 101, -22, 20, 4, -110, 52]
        byte[] c2_c2 = c2.c2.toByteArray(); // [32, -81, 73, 24, -81, 61, -112, -2, 115, 51, -41, -68, -48, -118, -92, -61]
        byte[] c2_concat = Bytes.concat(c2_c1, c2_c2);

//        assertArrayEquals(new byte[]{1, 72, 105, -92, 1, 84, -74, 54, 2, 61, -54, 101, -22, 20, 4, -110, 52, 32, -81, 73, 24, -81, 61, -112, -2, 115, 51, -41, -68, -48, -118, -92, -61}, c2_concat);

        byte[] c1_c2_concat = Bytes.concat(c1_concat, c2_concat);

        assertArrayEquals(c1_c2_concat, new BigInteger(c1_c2_concat).toByteArray());

        byte[] concatenated = new byte[]{};
        for (int i = 0; i < 4; i++) {
            switch (i) {
                case 0:
                    concatenated = Bytes.concat(concatenated, c1_c1);
                    break;
                case 1:
                    concatenated = Bytes.concat(concatenated, c1_c2);
                    break;
                case 2:
                    concatenated = Bytes.concat(concatenated, c2_c1);
                    break;
                case 3:
                    concatenated = Bytes.concat(concatenated, c2_c2);
                    break;
            }
        }
        assertArrayEquals(c1_c2_concat, concatenated);
    }

    @Test
    void TestCipherTextMultiply_Randomness_Cancel_out() {
        BigInteger p = elgamal.getDescription().p;
        BigInteger q = elgamal.getDescription().q;
        BigInteger r = UTIL.getRandomElement(q, new Random(0));
        BigInteger m = BigInteger.TEN;

        Ciphertext c = elgamal.exponentialEncrypt(BigInteger.ONE, pk, r);
        Ciphertext c_neg = elgamal.exponentialEncrypt(BigInteger.ONE, pk, r.negate());

        // Enc_pk(1; r) * Enc_pk(1; -r) = Enc_pk(2)
        Ciphertext result = c.multiply(c_neg, p);
        Ciphertext expected = elgamal.exponentialEncrypt(BigInteger.TWO, pk, BigInteger.ZERO);

        assertEquals(expected, result);
    }

    @Test
    void TestCipherTextInverse() {
        BigInteger p = elgamal.getDescription().p;
        BigInteger q = elgamal.getDescription().q;
        BigInteger r = UTIL.getRandomElement(q, new Random(0));
        BigInteger m = BigInteger.TEN;

        Ciphertext c = elgamal.exponentialEncrypt(BigInteger.ONE, pk, r); // (g^r, g^1 * h^r)
        Ciphertext c_neg = c.modInverse(p); // (g^{-r}, g^{-1} * h^{-r})

        // c * c^{-1} = 0
        Ciphertext result = c.multiply(c_neg, p);
        Ciphertext expected = elgamal.exponentialEncrypt(BigInteger.ZERO, pk, BigInteger.ZERO);

        assertEquals(expected, result);
    }


    @Test
    void TestCipherTextInverseVSNeg() {
        // Enc(m,r^-1) should equal Enc(m,r)^-1.
        BigInteger p = elgamal.getDescription().p;
        BigInteger q = elgamal.getDescription().q;
        BigInteger r = UTIL.getRandomElement(q, new Random(0));

        Ciphertext c_inv = elgamal.exponentialEncrypt(BigInteger.ZERO, pk, r).modInverse(p); // (g^r, g^0 * h^r)
         // (g^{-r}, g^{-1} * h^{-r})
        Ciphertext c_neg = elgamal.exponentialEncrypt(BigInteger.ZERO, pk, r.negate()); //(g^{-r}, g^{0} * h^{-r})

        assertEquals(c_inv, c_neg);
    }


    @Test
    void TestCipherTextRandomnessComposition() {
        // Enc(m,r^-1) should equal Enc(m,r)^-1.
        BigInteger p = elgamal.getDescription().p;
        BigInteger q = elgamal.getDescription().q;

        BigInteger e = BigInteger.ZERO;
        BigInteger r = UTIL.getRandomElement(q, new Random(0));
        BigInteger r1 = UTIL.getRandomElement(q, new Random(1));

        // Reencrypt c using c1(encrypted neutral element)
        Ciphertext c = elgamal.exponentialEncrypt(BigInteger.TEN, pk, r);
        Ciphertext c1 = elgamal.exponentialEncrypt(e, pk, r1);
        Ciphertext result = elgamal.exponentialEncrypt(BigInteger.valueOf(10), pk, r.add(r1));

        //  Enc_pk(10; r) * Enc_pk(e; r1) = Enc_pk(10; r + r1)
        Ciphertext expected = c.multiply(c1, p);
        assertEquals(expected, result);

        // Recover original cipher text by multiply by negated r1
        Ciphertext c1_inv = elgamal.exponentialEncrypt(e, pk, r1.negate());
        Ciphertext recoveredCiphertext = result.multiply(c1_inv, p);
        assertEquals(c, recoveredCiphertext);
    }

}
