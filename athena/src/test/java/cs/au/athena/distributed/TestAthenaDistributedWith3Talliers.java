package cs.au.athena.distributed;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.AthenaImpl;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.athena.RegisterStruct;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.factory.MainAthenaFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.CoreMatchers.notNullValue;


@Tag("TestAthenaWith3Talliers")
@DisplayName("Test Athena with 3 talliers")
public class TestAthenaDistributedWith3Talliers {


    @Test
    void TestWith3Talliers() throws InterruptedException {
        int tallierCount = 3;
        int kappa = CONSTANTS.KAPPA;
        int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
        MainAthenaFactory factory = new MainAthenaFactory(tallierCount, kappa);

        AthenaImpl athena = new AthenaImpl(factory);
        Map<Integer,ElGamalSK> talliersSK_HACKY_ASF = new HashMap<>();

        Function<Integer, Runnable> newRunnable =
                (tallierIndex) ->
                        () -> {
                            ElGamalSK T_i_sk = athena.Setup(tallierIndex, nc, kappa);
                            talliersSK_HACKY_ASF.put(tallierIndex, T_i_sk);
                            try {
                                Thread.sleep(10000);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                            MatcherAssert.assertThat("", T_i_sk.sk, is(not(BigInteger.ZERO)));
                        };

        Thread t1 = new Thread(newRunnable.apply(1));
        Thread t2 = new Thread(newRunnable.apply(2));
        Thread t3 = new Thread(newRunnable.apply(3));

        /*
         * Start the threads
         */
        t1.start();
        t2.start();
        t3.start();

        /*
         * Wait for them to finish.
         */
        t1.join();
        t2.join();
        t3.join();


        // Register and Vote
        registerAndVote(2, factory, athena, nc, kappa);
        registerAndVote(2, factory, athena, nc, kappa);
        registerAndVote(4, factory, athena, nc, kappa);
        registerAndVote(2, factory, athena, nc, kappa);

        System.err.println("--".repeat(30) + "> SLEEPING FOR 5 sec.");
        Thread.sleep(5 * 1000);
        System.err.println("--".repeat(30) + "> DONE SLEEPING");

        // Tally votes
        Function<Integer, Runnable> tallyRunnable =
                (tallierIndex) ->
                        () -> {
                            ElGamalSK T_i_sk = talliersSK_HACKY_ASF.get(tallierIndex);
                            System.err.println("--".repeat(30) + "> Tally T"+ tallierIndex + " is tallying");

                            Map<Integer, Integer> map = athena.Tally(tallierIndex, T_i_sk, nc, kappa);
                            try {
                                Thread.sleep(10000);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                            MatcherAssert.assertThat("", map, notNullValue());
                        };

        Thread t1_tally = new Thread(tallyRunnable.apply(1));
        Thread t2_tally = new Thread(tallyRunnable.apply(2));
        Thread t3_tally = new Thread(tallyRunnable.apply(3));

        t1_tally.start();
        t2_tally.start();
        t3_tally.start();

        t1_tally.join();
        t2_tally.join();
        t3_tally.join();

        // Verify election
        boolean verification = athena.Verify(kappa);
        MatcherAssert.assertThat("Verify the election, should be true/valid", verification, is(true));

    }

    private void registerAndVote(int voteToCast, AthenaFactory factory, AthenaImpl athena, int nc, int kappa) throws InterruptedException {
        /********************************/
        RegisterStruct registerResult = athena.Register(kappa);
        MatcherAssert.assertThat("pd != null", registerResult.pd, notNullValue());
        MatcherAssert.assertThat("d != null", registerResult.d, notNullValue());
        Thread.sleep(1000);

        int cnt = 1;
        Ballot ballot = athena.Vote(registerResult.d, voteToCast, cnt, nc, kappa);
        factory.getBulletinBoard().publishBallot(ballot); // VERY IMPORTANT! Instead just use a Voter
        MatcherAssert.assertThat("b[1]=pubcred != null", ballot.getPublicCredential(), notNullValue());
        /********************************/}
}
