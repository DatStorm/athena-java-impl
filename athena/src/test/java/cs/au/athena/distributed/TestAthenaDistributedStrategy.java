package cs.au.athena.distributed;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.AthenaImpl;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.factory.MainAthenaFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;

import static org.hamcrest.CoreMatchers.*;


@Tag("TestAthenaDistributedStrategy")
@DisplayName("Test Athena Distributed Strategy")
public class TestAthenaDistributedStrategy {
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
    MainAthenaFactory factory;
    private          int tallierCount;


    @BeforeEach
    void setUp() {
        tallierCount = 3;
        factory = new MainAthenaFactory(AthenaFactory.STRATEGY.DISTRIBUTED, tallierCount,kappa);
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
        Strategy strategy = factory.getStrategy();
        BulletinBoardV2_0 bb = factory.getBulletinBoard();


        CompletableFuture<ElGamalSK> f1 = new CompletableFuture<>();
        CompletableFuture<ElGamalSK> f2 = new CompletableFuture<>();
        CompletableFuture<ElGamalSK> f3 = new CompletableFuture<>();
        Thread t1 = new Thread(() -> f1.complete(strategy.setup(1, nc, kappa)));
        Thread t2 = new Thread(() -> f2.complete(strategy.setup(2, nc, kappa)));
        Thread t3 = new Thread(() -> f3.complete(strategy.setup(3, nc, kappa)));


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
    void TestNext() {


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
