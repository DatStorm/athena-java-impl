package elgamal;

import org.junit.jupiter.api.*;
import project.CONSTANTS;
import project.UTIL;
import project.athena.AthenaCommon;
import project.elgamal.Ciphertext;
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
    private ElGamal elGamal;
    private ElGamalSK sk;
    private ElGamalPK pk;

    private int nbits;


    @BeforeEach
    void setUp() {
        nbits = 32 * Byte.SIZE;
//        nbits = 32;

        random = new SecureRandom();
        elGamal = new ElGamal(nbits, CONSTANTS.MSG_SPACE_LENGTH,  random);
        sk = elGamal.generateSK();
        pk = elGamal.generatePk(sk);

    }

//    @RepeatedTest(100)
    @Test
    void TestGroup() {
        BigInteger g = pk.getGroup().getG();
        BigInteger p = pk.getGroup().getP();
        BigInteger q = pk.getGroup().getQ();

        assertEquals(BigInteger.ONE, g.modPow(q, p));
    }

//    @RepeatedTest(100)
    @Test
    void TestRandomLong() {
        ElGamal elGamal = new ElGamal(Long.SIZE, CONSTANTS.MSG_SPACE_LENGTH, new Random(CONSTANTS.RANDOM_SEED));

        ElGamalSK sk = elGamal.generateSK();
        ElGamalPK pk = elGamal.generatePk(sk);

        // Generate strictly positive long.
        long value;
        do {
            value = random.nextLong();
        } while (Long.signum(value) != 1);

        // m
        BigInteger msg = BigInteger.valueOf(value);

        // g^m
        BigInteger expected = pk.getGroup().g.modPow(msg,pk.getGroup().p);

        // Enc_pk(m)=(g^r, g^m*h^r)
        Ciphertext c = elGamal.encrypt(msg, pk);

        // g^m = Dec_sk(c)
        BigInteger result = elGamal.decrypt(c, sk);

        assertEquals(expected, result);
    }


    @Test
    void TestElGamalLarge() {
        BigInteger msg = BigInteger.TWO.pow(nbits).subtract(BigInteger.ONE); //2^nbits-1

        ElGamalSK sk = elGamal.generateSK();
        ElGamalPK pk = elGamal.generatePk(sk);

        // g^m
        BigInteger expected = pk.getGroup().g.modPow(msg,pk.getGroup().p);

        // Enc_pk(m)=(g^r, g^m*h^r)
        Ciphertext c = elGamal.encrypt(msg, pk);
        BigInteger result = elGamal.decrypt(c, sk);

        assertEquals(expected, result);
    }

    @Test
    void TestElGamalDescription() {
        ElGamal elGamal1 = new ElGamal(Long.SIZE, CONSTANTS.MSG_SPACE_LENGTH, new Random(CONSTANTS.RANDOM_SEED));
        ElGamal elGamal2 = new ElGamal(elGamal1.getDescription(),CONSTANTS.MSG_SPACE_LENGTH ,random);

        ElGamalSK sk = elGamal1.generateSK();
        ElGamalPK pk = elGamal1.generatePk(sk);

        // Generate strictly positive long.
        long value;
        do {
            value = random.nextLong();
        } while (Long.signum(value) != 1);

        // m
        BigInteger msg = BigInteger.valueOf(value);


        // g^m
        BigInteger expected = pk.getGroup().g.modPow(msg,pk.getGroup().p);

        // Enc_pk(m)=(g^r, g^m*h^r)
        Ciphertext c = elGamal1.encrypt(msg, pk);

        // g^m = Dec_sk(c)
        BigInteger result = elGamal2.decrypt(c, sk);

        assertEquals(expected, result);
    }

    @Test
    void TestHomoCombinations() {
        BigInteger g = pk.getGroup().getG();
        BigInteger p = pk.getGroup().getP();
        BigInteger q = pk.getGroup().getQ();


        // Combined d with -d. Should yeild an encryption of 1
        BigInteger d = UTIL.getRandomElement(q, random);
        Ciphertext publicCredential = elGamal.encrypt(d, pk);
        Ciphertext encryptedNegatedPrivateCredential = elGamal.encrypt(d.negate().mod(q).add(q).mod(q), pk);
        Ciphertext combinedCredential = publicCredential.multiply(encryptedNegatedPrivateCredential, p);

        // Nonce
        BigInteger n = UTIL.getRandomElement(q, random);
        Ciphertext noncedCombinedCredential = AthenaCommon.homoCombination(combinedCredential, n, p);

        // Decrypt
        BigInteger expected = BigInteger.ONE;
        BigInteger result = elGamal.decryptWithoutLookup(noncedCombinedCredential, sk);



        assertEquals(expected, result, "should be the same, 1 == 1" );

    }
}
