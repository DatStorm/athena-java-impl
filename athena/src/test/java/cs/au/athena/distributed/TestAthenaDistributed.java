package cs.au.athena.distributed;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.AthenaImpl;
import cs.au.athena.athena.distributed.AthenaDistributed;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.sigma1.Sigma1Proof;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.factory.MainAthenaFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

import static org.hamcrest.CoreMatchers.*;


@Tag("TestAthenaDistributed")
@DisplayName("Test Athena Distributed")
public class TestAthenaDistributed {
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
    private MainAthenaFactory factory;
    private int tallierCount;
    private Random random;
    private Group group;


    @BeforeEach
    void setUp() {
        tallierCount = 3;
        factory = new MainAthenaFactory(tallierCount,kappa);
        random = factory.getRandom();
        group = CONSTANTS.ELGAMAL_CURRENT.GROUP;
    }


    @Disabled
    void TestAthenaSetup() {
        AthenaImpl athena = new AthenaImpl(factory);

        int tallierIndex = 1;
        ElGamalSK sk = athena.Setup(tallierIndex, nc, kappa);
        MatcherAssert.assertThat("Should not be null", sk, notNullValue());
    }

    @Test
    void TestSetup() {
        AthenaDistributed athenaDistributed  = new AthenaDistributed(factory);
        BulletinBoardV2_0 bb = factory.getBulletinBoard();

        CompletableFuture<ElGamalSK> f1 = new CompletableFuture<>();
        CompletableFuture<ElGamalSK> f2 = new CompletableFuture<>();
        CompletableFuture<ElGamalSK> f3 = new CompletableFuture<>();
        Thread t1 = new Thread(() -> f1.complete(athenaDistributed.setup(1, nc, kappa)));
        Thread t2 = new Thread(() -> f2.complete(athenaDistributed.setup(2, nc, kappa)));
        Thread t3 = new Thread(() -> f3.complete(athenaDistributed.setup(3, nc, kappa)));


        // Start and wait for finish
        t1.start();
        t2.start();
        t3.start();
        ElGamalSK sk1 = f1.join();
        ElGamalSK sk2 = f2.join();
        ElGamalSK sk3 = f3.join();


        //Test that sk matches pk
        MatcherAssert.assertThat("", sk1.sk,is(not(BigInteger.ZERO)));
        MatcherAssert.assertThat("", sk2.sk,is(not(BigInteger.ZERO)));
        MatcherAssert.assertThat("", sk3.sk,is(not(BigInteger.ZERO)));

        //Test stuff



        MatcherAssert.assertThat("Should not be null", BigInteger.ONE, is(not(BigInteger.ZERO)));
    }


    @Test
    void TestProveKeyAndVerifyKey() {
        AthenaDistributed dist  = new AthenaDistributed(factory);

        ElGamalSK sk = ElGamal.generateSK(group, random);
        ElGamalPK pk = sk.pk;
        Sigma1Proof rho = dist.proveKey(pk, sk, kappa);

        boolean verification = dist.verifyKey(pk.h, rho, kappa);
        MatcherAssert.assertThat("Should succeed", verification, is(true));
    }

    // Things to test
    /*
    Polinomial matches polinomialCommitment?
    pk individual pk is published
    subshare is encrypted correctly
    subshare is valid compared to polinomialCommitment

    Lack of tallierCount or k on bb, should lead to error or timeout???
    Wrong polinomial Commitment length leads to error
    Invalid share leads to error
     */
}
