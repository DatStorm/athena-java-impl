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
    int k;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        elGamal = factory.getElgamal();
        random = new Random(CONSTANTS.RANDOM_SEED);
        group = CONSTANTS.ELGAMAL_32_BITS.GROUP;
        k = 1;
    }

    @Test
    void testSecretSharing() {
        Polynomial poly1 = Polynomial.newRandom(k, group, random);
        Polynomial poly2 = Polynomial.newRandom(k, group, random);
        Polynomial poly = poly1.add(poly2);

        // Make sk and pk
        ElGamalPK pk = new ElGamalPK(poly.getPointCommitment(0), group);

        // Compute shares of the secret key poly.eval(0)
        ElGamalSK sk1 = new ElGamalSK(group, poly.eval(1));
        ElGamalSK sk2 = new ElGamalSK(group, poly.eval(2));

        // Make ciphertext
//        GroupTheory.fromGToZq()
//        GroupTheory.fromZqToG()
        BigInteger expectedPlaintextElement = group.g.modPow(BigInteger.TEN, group.p);
        Ciphertext ciphertext = elGamal.encrypt(expectedPlaintextElement, pk);

        // Make decryption shares
        BigInteger share1 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk1);
        BigInteger share2 = SecretSharingUTIL.computeDecryptionShare(ciphertext, sk2);

        // Decrypt
        List<BigInteger> shares = Arrays.asList(share1, share2);
        List<Integer> S = Arrays.asList(1, 2);
        BigInteger resultPlaintextElement = SecretSharingUTIL.combineDecryptionShareAndDecrypt(ciphertext, shares, S, group);

        MatcherAssert.assertThat("We should be able to combine two ciphertexts", resultPlaintextElement, is(expectedPlaintextElement));
    }
}
