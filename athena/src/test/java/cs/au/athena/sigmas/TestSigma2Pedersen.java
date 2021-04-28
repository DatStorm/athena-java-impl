package cs.au.athena.sigmas;

import cs.au.athena.CONSTANTS;
import cs.au.athena.UTIL;
import cs.au.athena.dao.Sigma2Pedersen.Sigma2PedersenProof;
import cs.au.athena.dao.athena.UVector;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.sigma.Sigma2Pedersen;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;

@Tag("TestsSigma2")
@DisplayName("Test Sigma2")
public class TestSigma2Pedersen {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("TEST-Sigma2Pedersen");


    Sigma2Pedersen sigma2Pedersen;
    ElGamalSK sk;
    ElGamalPK pk;
    ElGamal elGamal;
    private static Random random;

    @BeforeAll
    static void setup() {
        random = new Random(0);
    }

    @BeforeEach
    void setupThis() {
        sigma2Pedersen = new Sigma2Pedersen(random);

        logger.info(MARKER,"BEFORE ELGAMAL");
        elGamal = new ElGamal(CONSTANTS.ELGAMAL_CURRENT.GROUP, 0, random);
        logger.info(MARKER,"AFTER ELGAMAL");

        this.sk = elGamal.generateSK();
        pk = this.sk.getPK();
        logger.info(MARKER,"SETUP DONE");

    }

    @RepeatedTest(10)
    void Test() {
        logger.info(MARKER,"TEST START");

        UVector uVector = mockUVector();

        BigInteger msg = UTIL.getRandomElement(pk.group.q, random);
        BigInteger r = UTIL.getRandomElement(pk.group.q, random);

        Ciphertext cipher = elGamal.exponentialEncrypt(msg, pk, r);
        Sigma2PedersenProof proof = sigma2Pedersen.proveCipher(cipher, msg, r, uVector, pk);

        boolean succes = Sigma2Pedersen.verifyCipher(cipher, proof, uVector, pk);
        MatcherAssert.assertThat("Should be correct", succes, is(true));


    }

    private UVector mockUVector() {
        Ciphertext mock = new Ciphertext(BigInteger.ONE, BigInteger.TWO);
        return new UVector(mock, mock, mock, BigInteger.ZERO);
    }
}
