package cs.au.athena.distributed;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.strategy.Strategy;
import cs.au.athena.athena.AthenaImpl;
import cs.au.athena.dao.athena.ElectionSetup;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.factory.MainAthenaFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;
import java.util.concurrent.Future;
import java.util.concurrent.CompletableFuture;

import static org.hamcrest.CoreMatchers.*;


@Tag("TestAthenaDistributedStrategy")
@DisplayName("Test Athena Distributed Strategy")
public class TestAthenaDistributedStrategy {
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
    MainAthenaFactory maFactory;

    @BeforeEach
    void setUp() {
        maFactory = new MainAthenaFactory(AthenaFactory.STRATEGY.DISTRIBUTED);
    }


    @Test
    void TestAthenaSetup() {
        AthenaImpl athena = new AthenaImpl(maFactory);
        ElectionSetup setup = athena.Setup(nc, kappa);
        MatcherAssert.assertThat("Should not be null", setup.sk, notNullValue());
    }

    @Test
    void TestGetElGamalSK() throws InterruptedException {
        Strategy strategy = maFactory.getStrategy();
        Random random = maFactory.getRandom();
        BulletinBoardV2_0 bb = maFactory.getBulletinBoard();

        int talliercount = 3;
        int atMostKBadTalliers = 2;
        bb.init(talliercount,atMostKBadTalliers);

        Group group = strategy.getGroup(kappa * 8 , random);

        CompletableFuture<ElGamalSK> f1 = new CompletableFuture<>();
        CompletableFuture<ElGamalSK> f2 = new CompletableFuture<>();
        CompletableFuture<ElGamalSK> f3 = new CompletableFuture<>();
        Thread t1 = new Thread(() -> f1.complete(strategy.getElGamalSK(1, group, random)));
        Thread t2 = new Thread(() -> f2.complete(strategy.getElGamalSK(2, group, random)));
        Thread t3 = new Thread(() -> f3.complete(strategy.getElGamalSK(3, group, random)));

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
