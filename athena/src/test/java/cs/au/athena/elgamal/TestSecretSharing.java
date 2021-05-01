package cs.au.athena.elgamal;

import cs.au.athena.CONSTANTS;
import cs.au.athena.Polynomial;
import cs.au.athena.SecretSharingUTIL;
import cs.au.athena.factory.Factory;
import cs.au.athena.factory.MainFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;

@Tag("TestSecretSharing")
@DisplayName("Test Secret Sharing.")
public class TestSecretSharing {
    Random random;
    Group group;
    ElGamal elGamal;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        elGamal = factory.getElgamal();
        random = new Random(CONSTANTS.RANDOM_SEED);
        group = CONSTANTS.ELGAMAL_2048_BITS.GROUP;
        group = CONSTANTS.ELGAMAL_32_BITS.GROUP;
    }


    @Test
    void testSecretSharingWithThreeSmall() {
        int eval_1 = 1;
        int eval_2 = 2;
        int eval_3 = 3;

        Polynomial poly1 = new Polynomial(Arrays.asList(BigInteger.valueOf(0),BigInteger.valueOf(1),BigInteger.valueOf(0)), group);
        Polynomial poly2 = new Polynomial(Arrays.asList(BigInteger.valueOf(0),BigInteger.valueOf(0),BigInteger.valueOf(0)), group);
        Polynomial poly3 = new Polynomial(Arrays.asList(BigInteger.valueOf(0),BigInteger.valueOf(0),BigInteger.valueOf(0)), group);
        Polynomial poly = poly1.add(poly2).add(poly3);

        MatcherAssert.assertThat("Poly check 1", poly.getCoefficients().get(0), is(BigInteger.ZERO));
        MatcherAssert.assertThat("Poly check 2", poly.getCoefficients().get(1), is(BigInteger.ONE));
        MatcherAssert.assertThat("Poly check 3", poly.getCoefficients().get(2), is(BigInteger.ZERO));


        // Make sk and pk
        ElGamalPK pk = new ElGamalPK(poly.getPointCommitment(0), group);

        // Compute shares of the secret key poly.eval(0)
        ElGamalSK sk1 = new ElGamalSK(group, poly.eval(eval_1));
        ElGamalSK sk2 = new ElGamalSK(group, poly.eval(eval_2));
        ElGamalSK sk3 = new ElGamalSK(group, poly.eval(eval_3));
        System.out.println("sk1: " + sk1.sk);
        System.out.println("sk2: " + sk2.sk);
        System.out.println("sk3: " + sk3.sk);

        // Make ciphertext
        BigInteger expectedPlaintext = BigInteger.valueOf(20);
        BigInteger expectedPlaintextElement = GroupTheory.fromZqToG(expectedPlaintext, group);
        System.out.println("plain: " + expectedPlaintextElement);
        System.out.println("group: " + group);

        Ciphertext ciphertext = elGamal.encrypt(expectedPlaintextElement, pk);
        System.out.println(ciphertext);


        // Make decryption shares
        BigInteger share1 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk1);
        BigInteger share2 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk2);
        BigInteger share3 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk3);
        System.out.println(share1);
        System.out.println(share2);
        System.out.println(share3);



        // Decrypt
        List<BigInteger> decryptionShares = Arrays.asList(share1, share2, share3);
        List<Integer> S = Arrays.asList(eval_1, eval_2, eval_3);
        BigInteger resultPlaintextElement = SecretSharingUTIL.combineDecryptionShareAndDecrypt(ciphertext, decryptionShares, S, group);
        BigInteger resultPlaintext = GroupTheory.fromGToZq(resultPlaintextElement, group);


        MatcherAssert.assertThat("We should be able to combine THREE-SMALL ciphertexts", resultPlaintext, is(expectedPlaintext));
    }


    @Test
    void testSecretSharingWithFour() {
        int k = 3;
        int eval_1 = 1;
        int eval_2 = 2;
        int eval_3 = 3;
        int eval_4 = 4;

        Polynomial poly1 = Polynomial.newRandom(k, group, random);
        Polynomial poly2 = Polynomial.newRandom(k, group, random);
        Polynomial poly3 = Polynomial.newRandom(k, group, random);
        Polynomial poly4 = Polynomial.newRandom(k, group, random);
        Polynomial poly = poly1.add(poly2).add(poly3).add(poly4);

        // Make sk and pk
        ElGamalPK pk = new ElGamalPK(poly.getPointCommitment(0), group);

        // Compute shares of the secret key poly.eval(0)
        ElGamalSK sk1 = new ElGamalSK(group, poly.eval(eval_1));
        ElGamalSK sk2 = new ElGamalSK(group, poly.eval(eval_2));
        ElGamalSK sk3 = new ElGamalSK(group, poly.eval(eval_3));
        ElGamalSK sk4 = new ElGamalSK(group, poly.eval(eval_4));

        // Make ciphertext
//        BigInteger expectedPlaintext = BigInteger.valueOf(20);
//        BigInteger expectedPlaintextElement = GroupTheory.fromZqToG(expectedPlaintext, group);
//        Ciphertext ciphertext = elGamal.encrypt(expectedPlaintextElement, pk);

        // Make ciphertext
        BigInteger val = BigInteger.valueOf(20);
        BigInteger expectedPlaintextElement = group.g.modPow(val, group.p); // = m = g^v
        Ciphertext ciphertext = elGamal.encrypt(expectedPlaintextElement, pk); // C=Enc(m)

        // Make decryption shares
        BigInteger share1 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk1);
        BigInteger share2 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk2);
        BigInteger share3 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk3);
        BigInteger share4 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk4);

        // Decrypt
        List<BigInteger> shares = Arrays.asList(share1, share2, share3, share4);
        List<Integer> S = Arrays.asList(eval_1, eval_2, eval_3, eval_4);
        BigInteger resultPlaintextElement = SecretSharingUTIL.combineDecryptionShareAndDecrypt(ciphertext, shares, S, group); // Dec(C)=m = g^v

        // Dec(C) =?= g^v
        MatcherAssert.assertThat("We should be able to combine FOUR ciphertexts", resultPlaintextElement, is(expectedPlaintextElement));
    }

    @Test
    void testSecretSharingWithThree() {
        int k = 2;
        int eval_1 = 1;
        int eval_2 = 2;
        int eval_3 = 3;

        Polynomial poly1 = Polynomial.newRandom(k, group, random);
        Polynomial poly2 = Polynomial.newRandom(k, group, random);
        Polynomial poly3 = Polynomial.newRandom(k, group, random);
        Polynomial poly = poly1.add(poly2).add(poly3);

        // Make sk and pk
        ElGamalPK pk = new ElGamalPK(poly.getPointCommitment(0), group);

        // Compute shares of the secret key poly.eval(0)
        ElGamalSK sk1 = new ElGamalSK(group, poly.eval(eval_1));
        ElGamalSK sk2 = new ElGamalSK(group, poly.eval(eval_2));
        ElGamalSK sk3 = new ElGamalSK(group, poly.eval(eval_3));

        // Make ciphertext
        BigInteger val = BigInteger.valueOf(20);
        BigInteger expectedPlaintextElement = group.g.modPow(val, group.p); // = m = g^v
        Ciphertext ciphertext = elGamal.encrypt(expectedPlaintextElement, pk); // C=Enc(m)

        // Make decryption shares
        BigInteger share1 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk1);
        BigInteger share2 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk2);
        BigInteger share3 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk3);

        // Decrypt
        List<BigInteger> shares = Arrays.asList(share1, share2, share3);
        List<Integer> S = Arrays.asList(eval_1, eval_2, eval_3);
        BigInteger resultPlaintextElement = SecretSharingUTIL.combineDecryptionShareAndDecrypt(ciphertext, shares, S, group); // Dec(C)=m = g^v

        // Dec(C) =?= g^v
        MatcherAssert.assertThat("We should be able to combine THREE ciphertexts", resultPlaintextElement, is(expectedPlaintextElement));
    }


    @Test
    void testSecretSharingWithTwo() {
        int eval_1 = 1;
        int eval_2 = 2;
        int k = 1;

        Polynomial poly1 = Polynomial.newRandom(k, group, random);
        Polynomial poly2 = Polynomial.newRandom(k, group, random);
        Polynomial poly = poly1.add(poly2);

        // Make sk and pk
        ElGamalPK pk = new ElGamalPK(poly.getPointCommitment(0), group);

        // Compute shares of the secret key poly.eval(0)
        ElGamalSK sk1 = new ElGamalSK(group, poly.eval(eval_1));
        ElGamalSK sk2 = new ElGamalSK(group, poly.eval(eval_2));

        // Make ciphertext
        BigInteger expectedPlaintextElement = group.g.modPow(BigInteger.TEN, group.p);
        Ciphertext ciphertext = elGamal.encrypt(expectedPlaintextElement, pk);

        // Make decryption shares
        BigInteger share1 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk1);
        BigInteger share2 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk2);

        // Decrypt
        List<BigInteger> shares = Arrays.asList(share1, share2);
        List<Integer> S = Arrays.asList(eval_1, eval_2);
        BigInteger resultPlaintextElement = SecretSharingUTIL.combineDecryptionShareAndDecrypt(ciphertext, shares, S, group);

        MatcherAssert.assertThat("We should be able to combine TWO ciphertexts", resultPlaintextElement, is(expectedPlaintextElement));
    }


    @Test
    void testSecretSharingWithThreeAndOneCommonPoly() {
        int eval_1 = 1;
        int eval_2 = 2;
        int eval_3 = 3;
        int k = 2;

        Polynomial poly = Polynomial.newRandom(k, group, random);

        // Make sk and pk
        ElGamalPK pk = new ElGamalPK(group.g.modPow(poly.eval(0),group.p), group);

        // Compute shares of the secret key poly.eval(0)
        ElGamalSK sk1 = new ElGamalSK(group, poly.eval(eval_1));
        ElGamalSK sk2 = new ElGamalSK(group, poly.eval(eval_2));
        ElGamalSK sk3 = new ElGamalSK(group, poly.eval(eval_3));

        // Make ciphertext
        BigInteger expectedPlaintextElement = group.g.modPow(BigInteger.TEN, group.p);
        Ciphertext ciphertext = elGamal.encrypt(expectedPlaintextElement, pk);

        // Make decryption shares
        BigInteger share1 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk1);
        BigInteger share2 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk2);
        BigInteger share3 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk3);

        // Decrypt
        List<BigInteger> shares = Arrays.asList(share1, share2, share3);
        List<Integer> S = Arrays.asList(eval_1, eval_2, eval_3);
        BigInteger resultPlaintextElement = SecretSharingUTIL.combineDecryptionShareAndDecrypt(ciphertext, shares, S, group);

        MatcherAssert.assertThat("We should be able to combine THREE-COMMON ciphertexts", resultPlaintextElement, is(expectedPlaintextElement));
    }


}
