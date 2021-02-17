package elgamal;

import org.junit.jupiter.api.*;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("TestElgamal")
@DisplayName("Test Elgamal Encryption+Decryption")
public class TestElgamal {


    private Random random;
    private int nbits;
    private ElGamal elGamal;

    @BeforeEach
    void setUp() {
        int nbits = 32 * Byte.SIZE;
        random = new SecureRandom();
        elGamal = new ElGamal(nbits);
    }

//    @RepeatedTest(100)
//    void TestRandomLong() {
//        ElGamal elGamal = new ElGamal(Long.SIZE);
//
//        ElGamalSK sk = elGamal.generateSK();
//        ElGamalPK pk = elGamal.generatePk(sk);
//
//        // Generate strictly positive long.
//        long value;
//        do {
//            value = random.nextLong();
//        } while (Long.signum(value) != 1);
//
//        BigInteger expected = BigInteger.valueOf(value);
//
//        Tuple c = elGamal.encrypt(expected, pk);
//        BigInteger result = elGamal.decrypt(c, sk);
//
//        assertEquals(expected, result);
//    }
//
//    @RepeatedTest(100)
//    void TestBitArrayIntegration() {
//        ElGamalSK sk = elGamal.generateSK();
//        ElGamalPK pk = elGamal.generatePk(sk);
//
//        BigInteger expected = new BitArray(nbits, random).toBigInteger();
//
//        Tuple c = elGamal.encrypt(expected, pk);
//        BigInteger result = elGamal.decrypt(c, sk);
//
//        assertEquals(expected, result);
//    }
//
//
//    @Test
//    void TestElGamalLarge() {
//        BigInteger expected = BigInteger.TWO.pow(nbits).subtract(BigInteger.ONE); //2^nbits-1
//        BigInteger sk = elGamal.generateSk();
//        Tuple pk = elGamal.generatePk(sk);
//
//        Tuple c = elGamal.encrypt(expected, pk);
//        BigInteger result = elGamal.decrypt(c, sk);
//
//        assertEquals(expected, result);
//    }
//
//    @Test
//    void TestElGamalDescription() {
//        ElGamal elGamal1 = new ElGamal(Long.SIZE);
//        ElGamal elGamal2 = new ElGamal(elGamal1.getDescription());
//
//        BigInteger sk = elGamal1.generateSk();
//        Tuple pk = elGamal1.generatePk(sk);
//
//        // Generate strictly positive long.
//        long value;
//        do {
//            value = random.nextLong();
//        } while (Long.signum(value) != 1);
//
//        BigInteger expected = BigInteger.valueOf(value);
//
//        Tuple c = elGamal1.encrypt(expected, pk);
//        BigInteger result = elGamal2.decrypt(c, sk);
//
//        assertEquals(expected, result);
//    }
}
