package cs.au.athena.distributed;

import cs.au.athena.CONSTANTS;
import cs.au.athena.UTIL;
import cs.au.athena.athena.Athena;
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
import java.util.*;
import java.util.function.Function;

import static org.hamcrest.CoreMatchers.*;


@Tag("TestAthenaWithXTalliers")
@DisplayName("Test Athena with X talliers")
public class TestAthenaDistributedWithXTalliers {


    /***********************************
     ********* With 1 talliers *********
     **********************************/
    @Test
    void TestWith1TalliersAnd1Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			29
//        Athena Verify: Execution time in seconds : 			0
        int tallierCount = 1;
        int numVotes = 1;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith1TalliersAnd5Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			53
//        Athena Verify: Execution time in seconds : 			1
        int tallierCount = 1;
        int numVotes = 5;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith1TalliersAnd10Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			84
//        Athena Verify: Execution time in seconds : 			3
        int tallierCount = 1;
        int numVotes = 10;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith1TalliersAnd20Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			145
//        Athena Verify: Execution time in seconds : 			6
        int tallierCount = 1;
        int numVotes = 20;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith1TalliersAnd50Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			340
//        Athena Verify: Execution time in seconds : 			16
        int tallierCount = 1;
        int numVotes = 50;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith1TalliersAnd100Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			697
//        Athena Verify: Execution time in seconds :            31
        int tallierCount = 1;
        int numVotes = 100;
        runAthena(tallierCount, numVotes);
    }
    @Test
    void TestWith1TalliersAnd200Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			?
//        Athena Verify: Execution time in seconds :            ?
        int tallierCount = 1;
        int numVotes = 200;
        runAthena(tallierCount, numVotes);
    }
    @Test
    void TestWith1TalliersAnd500Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			?
//        Athena Verify: Execution time in seconds :            ?
        int tallierCount = 1;
        int numVotes = 500;
        runAthena(tallierCount, numVotes);
    }


    /***********************************
     ********* With 3 talliers *********
     **********************************/
    @Test
    void TestWith3TalliersAnd1Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			57
//        Athena Verify: Execution time in seconds : 			7
        int tallierCount = 3;
        int numVotes = 1;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith3TalliersAnd5Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			151
//        Athena Verify: Execution time in seconds : 			35
        int tallierCount = 3;
        int numVotes = 5;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith3TalliersAnd10Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			265
//        Athena Verify: Execution time in seconds : 			70
        int tallierCount = 3;
        int numVotes = 10;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith3TalliersAnd20Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			506
//        Athena Verify: Execution time in seconds : 			147
        int tallierCount = 3;
        int numVotes = 20;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith3TalliersAnd50Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			1354
//        Athena Verify: Execution time in seconds : 			389
        int tallierCount = 3;
        int numVotes = 50;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith3TalliersAnd100Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			2983
//        Athena Verify: Execution time in seconds : 			841
        int tallierCount = 3;
        int numVotes = 100;
        runAthena(tallierCount, numVotes);
    }
    @Test
    void TestWith3TalliersAnd200Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			?
//        Athena Verify: Execution time in seconds : 			?
        int tallierCount = 3;
        int numVotes = 200;
        runAthena(tallierCount, numVotes);
    }
    @Test
    void TestWith3TalliersAnd500Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			?
//        Athena Verify: Execution time in seconds : 			?
        int tallierCount = 3;
        int numVotes = 500;
        runAthena(tallierCount, numVotes);
    }


    /***********************************
     ********* With 7 talliers *********
     **********************************/
    @Test
    void TestWith7TalliersAnd1Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			141
//        Athena Verify: Execution time in seconds : 			21
        int tallierCount = 7;
        int numVotes = 1;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith7TalliersAnd5Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			350
//        Athena Verify: Execution time in seconds : 			106
        int tallierCount = 7;
        int numVotes = 5;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith7TalliersAnd10Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			633
//        Athena Verify: Execution time in seconds : 			211
        int tallierCount = 7;
        int numVotes = 10;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith7TalliersAnd20Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			1217
//        Athena Verify: Execution time in seconds : 			431
        int tallierCount = 7;
        int numVotes = 20;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith7TalliersAnd50Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			3332
//        Athena Verify: Execution time in seconds : 			1136
        int tallierCount = 7;
        int numVotes = 50;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith7TalliersAnd100Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			8221
//        Athena Verify: Execution time in seconds : 			2476
        int tallierCount = 7;
        int numVotes = 100;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith7TalliersAnd200Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			?
//        Athena Verify: Execution time in seconds : 			?
        int tallierCount = 7;
        int numVotes = 200;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith7TalliersAnd500Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			?
//        Athena Verify: Execution time in seconds : 			?
        int tallierCount = 7;
        int numVotes = 500;
        runAthena(tallierCount, numVotes);
    }



    /***********************************
     ******** With 15 talliers *********
     **********************************/
    @Test
    void TestWith15TalliersAnd1Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			663
//        Athena Verify: Execution time in seconds : 			47
        int tallierCount = 15;
        int numVotes = 1;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith15TalliersAnd5Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			1429
//        Athena Verify: Execution time in seconds : 			243
        int tallierCount = 15;
        int numVotes = 5;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith15TalliersAnd10Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			2356
//        Athena Verify: Execution time in seconds : 			488
        int tallierCount = 15;
        int numVotes = 10;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith15TalliersAnd20Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			4438
//        Athena Verify: Execution time in seconds : 			961
        int tallierCount = 15;
        int numVotes = 20;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith15TalliersAnd50Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			13293
//        Athena Verify: Execution time in seconds : 			2608
        int tallierCount = 15;
        int numVotes = 50;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith15TalliersAnd100Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			33412
//        Athena Verify: Execution time in seconds : 			5876
        int tallierCount = 15;
        int numVotes = 100;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith15TalliersAnd200Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			1392 (no mixnet)
//        Athena Verify: Execution time in seconds : 			153 (no mixnet)
        int tallierCount = 15;
        int numVotes = 200;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith15TalliersAnd500Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			? 2722 (no mixnet)
//        Athena Verify: Execution time in seconds : 			389 (no mixnet)
        int tallierCount = 15;
        int numVotes = 500;
        runAthena(tallierCount, numVotes);
    }

    @Test
    void TestWith15TalliersAnd1000Votes() throws InterruptedException {
//        Athena Tally: Execution time in seconds : 			?
//        Athena Verify: Execution time in seconds : 			?
        int tallierCount = 15;
        int numVotes = 1000;
        runAthena(tallierCount, numVotes);
    }


    private void runAthena(int tallierCount, int numVotes) throws InterruptedException {
        int kappa = CONSTANTS.KAPPA;
        int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
        MainAthenaFactory factory = new MainAthenaFactory(tallierCount, kappa);

        Athena athena = new AthenaImpl(factory);
        Map<Integer, ElGamalSK> talliersSK_HACKY_ASF = new HashMap<>();

        /** *********/
        long startTime = System.nanoTime();

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

        List<Thread> threads = new ArrayList<>(tallierCount);
        for (int i = 1; i <= tallierCount; i++) {
            Thread ti = new Thread(newRunnable.apply(i));
            threads.add(ti);
        }

        /*
         * Start the threads
         */
        for (Thread t : threads) {
            t.start();

        }

        /*
         * Wait for them to finish.
         */
        for (Thread t : threads) {
            t.join();

        }


        // Register and Vote
        for (int i = 0; i < numVotes; i++) {
            int randVote = new Random().nextInt(nc);
            registerAndVote(randVote, factory, athena, nc, kappa);

        }


//        System.err.println("--".repeat(30) + "> SLEEPING FOR 5 sec.");
        Thread.sleep(numVotes * 1000L);
//        System.err.println("--".repeat(30) + "> DONE SLEEPING");

        // Tally votes
        final Map<Integer, Integer>[] tallyMap = new Map[tallierCount];

        Function<Integer, Runnable> tallyRunnable =
                (tallierIndex) ->
                        () -> {
                            ElGamalSK T_i_sk = talliersSK_HACKY_ASF.get(tallierIndex);

                            int mapIndex = tallierIndex - 1;
                            tallyMap[mapIndex] = athena.Tally(tallierIndex, T_i_sk, nc, kappa);

                            try {
                                Thread.sleep(10000);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                            MatcherAssert.assertThat("", tallyMap[mapIndex], notNullValue());
                        };

        List<Thread> threadsTally = new ArrayList<>(tallierCount);
        for (int i = 1; i <= tallierCount; i++) {
            Thread ti = new Thread(tallyRunnable.apply(i));
            threadsTally.add(ti);
        }

        /*
         * Start the threads
         */
        for (Thread t : threadsTally) {
            t.start();

        }

        /*
         * Wait for them to finish.
         */
        for (Thread t : threadsTally) {
            t.join();

        }

        long endTime = System.nanoTime();
        UTIL.printEvalMetrics("Athena Tally: ", startTime, endTime);

//        System.out.println(UTIL.prettyPrintTallyResult(tallyMap[0]));


        // Verify election
        startTime = System.nanoTime();

        boolean verification = athena.Verify(kappa);
        endTime = System.nanoTime();
        UTIL.printEvalMetrics("Athena Verify: ", startTime, endTime);

        MatcherAssert.assertThat("Verify the election, should be true/valid", verification, is(true));
    }

    private void registerAndVote(int voteToCast, AthenaFactory factory, Athena athena, int nc, int kappa) throws InterruptedException {
        RegisterStruct registerResult = athena.Register(kappa);
        MatcherAssert.assertThat("pd != null", registerResult.pd, notNullValue());
        MatcherAssert.assertThat("d != null", registerResult.d, notNullValue());
        Thread.sleep(1000);

        int cnt = 1;
        Ballot ballot = athena.Vote(registerResult.d, voteToCast, cnt, nc, kappa);
        factory.getBulletinBoard().publishBallot(ballot); // VERY IMPORTANT! Instead just use a Voter
        MatcherAssert.assertThat("b[1]=pubcred != null", ballot.getPublicCredential(), notNullValue());
    }
}
