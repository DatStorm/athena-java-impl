package cs.au.athena.elgamal;

import cs.au.athena.CONSTANTS;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.*;
import cs.au.athena.UTIL;
import cs.au.athena.athena.AthenaCommon;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("TestElgamal")
@DisplayName("Test Elgamal Encryption+Decryption")
public class TestElGamal {
    private Random random;
    private ElGamal elGamal;
    private ElGamalSK sk;
    private ElGamalPK pk;
    private int bitlength;



    @BeforeEach
    void setUp() {
        bitlength = 32 * Byte.SIZE; // = 32*8 = 256
        random = new SecureRandom();


        // Current version is 32 bits....
        BigInteger p = CONSTANTS.ELGAMAL_CURRENT.ELGAMAL_P;
        BigInteger q = CONSTANTS.ELGAMAL_CURRENT.ELGAMAL_Q;
        BigInteger g = CONSTANTS.ELGAMAL_CURRENT.ELGAMAL_G;

        Group group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
        elGamal = new ElGamal(group, CONSTANTS.MSG_SPACE_LENGTH, random);
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

    @Test
    void TestConstantGroup() {
        BigInteger g = CONSTANTS.ELGAMAL_CURRENT.GROUP.getG();
        BigInteger p = CONSTANTS.ELGAMAL_CURRENT.GROUP.getP();
        BigInteger q = CONSTANTS.ELGAMAL_CURRENT.GROUP.getQ();

        BigInteger plain = BigInteger.TEN;
        Ciphertext cipher = elGamal.encrypt(plain, pk);
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
        Ciphertext c = elGamal.exponentialEncrypt(msg, pk);

        // g^m = Dec_sk(c)
        BigInteger result = ElGamal.decrypt(c, sk);

        assertEquals(expected, result);
    }


    @Test
    void TestElGamalLarge() {
        BigInteger msg = BigInteger.TWO.pow(bitlength).subtract(BigInteger.ONE); //2^nbits-1

        ElGamalSK sk = elGamal.generateSK();
        ElGamalPK pk = elGamal.generatePk(sk);

        // g^m
        BigInteger expected = pk.getGroup().g.modPow(msg,pk.getGroup().p);

        // Enc_pk(m)=(g^r, g^m*h^r)
        Ciphertext c = elGamal.exponentialEncrypt(msg, pk);
        BigInteger result = ElGamal.decrypt(c, sk);

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
        Ciphertext c = elGamal1.exponentialEncrypt(msg, pk);

        // g^m = Dec_sk(c)
        BigInteger result = ElGamal.decrypt(c, sk);

        assertEquals(expected, result);
    }

    @Test
    void TestHomoCombinations() {
        BigInteger g = pk.getGroup().getG();
        BigInteger p = pk.getGroup().getP();
        BigInteger q = pk.getGroup().getQ();


        // Combined d with -d. Should yeild an encryption of 1
        BigInteger d = UTIL.getRandomElement(q, random);
        Ciphertext publicCredential = elGamal.exponentialEncrypt(d, pk);
        Ciphertext encryptedNegatedPrivateCredential = elGamal.exponentialEncrypt(d.negate().mod(q).add(q).mod(q), pk);
        Ciphertext combinedCredential = publicCredential.multiply(encryptedNegatedPrivateCredential, pk.group);

        // Nonce
        BigInteger n = UTIL.getRandomElement(q, random);
        Ciphertext noncedCombinedCredential = AthenaCommon.homoCombination(combinedCredential, n, pk.getGroup());

        // Decrypt
        BigInteger expected = BigInteger.ONE;
        BigInteger result = ElGamal.decrypt(noncedCombinedCredential, sk);



        assertEquals(expected, result, "should be the same, 1 == 1" );

    }


    @Test
    void TestExponentialElGamal() {
        BigInteger expected = BigInteger.TEN;
        Ciphertext ciphertext = elGamal.exponentialEncrypt(expected, pk);
        Integer result = elGamal.exponentialDecrypt(ciphertext, sk);

        assertEquals(expected.intValueExact(), result.intValue());
    }

    @Disabled
    @Test
    void TestLookupTableComputationTime() {
        // Version 2048 bits....
        BigInteger p = CONSTANTS.ELGAMAL_2048_BITS.ELGAMAL_P;
        BigInteger q = CONSTANTS.ELGAMAL_2048_BITS.ELGAMAL_Q;
        BigInteger g = CONSTANTS.ELGAMAL_2048_BITS.ELGAMAL_G;

        Group group = new Group(p, q, g);
        int messageSpaceLength = (int) Math.pow(2, 10); // 1.000.000
        elGamal = new ElGamal(group, messageSpaceLength, random);
    }

    @Test
    void ComputeNewEfficientGroup() {
        // Version 2048 bits....
        Random rand = new SecureRandom();

        int bitlength = CONSTANTS.ELGAMAL_2048_BITS.ELGAMAL_BIT_LENGTH;
        Group group = ElGamal.generateEfficientGroup(bitlength, rand);


        System.out.println("p: " + group.p);
        System.out.println("q: " + group.q);
        System.out.println("g: " + group.g);
    }

    @Test
    void TestDiegoGroup() {
        // Version 2048 bits....
//        Group group = CONSTANTS.ELGAMAL__DIFFIE_HELLMAN_GROUP__.GROUP;
        Group group = CONSTANTS.ELGAMAL_2048_BITS.GROUP;

        System.out.println("q length" + group.q.bitLength());
        System.out.println("p length" + group.p.bitLength());

        boolean probable_p_Prime = group.p.isProbablePrime(32);
        boolean probable_q_Prime = group.q.isProbablePrime(32);

        MatcherAssert.assertThat("Q is not prime", probable_q_Prime, is(true));
        MatcherAssert.assertThat("P is not prime", probable_p_Prime, is(true));

        //p=2q+1 => q er 1024 bits WRONG => q er 2045 bits


        // Chech that g is a generator of the group.
        for (int i = 0; i < 20; i++) {
            boolean success = group.g.pow(i).modPow(group.q, group.p).equals(BigInteger.ONE);
            MatcherAssert.assertThat(String.format("Incorrect i=%d",i), success, is(true));

        }

    }



}
