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


    @Test
    void TestWithXTalliers() throws InterruptedException {
        int tallierCount = 3;
        int numBallots = 1;
        int kappa = CONSTANTS.KAPPA;
        int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
        MainAthenaFactory factory = new MainAthenaFactory(tallierCount, kappa);

        AthenaImpl athena = new AthenaImpl(factory);

        long startTime = System.nanoTime();


        /** *********/
        Map<Integer, ElGamalSK> FAKE_sk_Map = setupForXTalliers(tallierCount, athena, nc, kappa);

        // Register and Vote
        voteForYBallots(numBallots, factory,athena,nc,kappa);


        // Tally votes
        List<Map<Integer, Integer>> listOfTallyVotes = tallyForXTalliers(tallierCount,FAKE_sk_Map,athena,nc,kappa);

        long endTime = System.nanoTime();
        UTIL.printEvalMetrics("Athena Tally: ", startTime, endTime);

        System.out.println(UTIL.prettyPrintTallyResult(listOfTallyVotes.get(0)));

        // Verify election
        startTime = System.nanoTime();
        boolean verification = athena.Verify(kappa);
        endTime = System.nanoTime();
        UTIL.printEvalMetrics("Athena Verify: ", startTime, endTime);

        MatcherAssert.assertThat("Verify the election, should be true/valid", verification, is(true));

    }

    private List<Map<Integer, Integer>> tallyForXTalliers(int tallierCount, Map<Integer,ElGamalSK> talliersSK_HACKY_ASF,Athena athena, int nc, int kappa) throws InterruptedException {
        List<Map<Integer, Integer>> res = new ArrayList<>(tallierCount);

        Function<Integer, Runnable> tallyRunnable =
                (tallierIndex) ->
                        () -> {
                            ElGamalSK T_i_sk = talliersSK_HACKY_ASF.get(tallierIndex);
//                            System.err.println("--".repeat(30) + "> Tally T"+ tallierIndex + " is tallying");

                            Map<Integer, Integer> tally_map = athena.Tally(tallierIndex, T_i_sk, nc, kappa);
                            res.add(tallierIndex - 1, tally_map);

                            try {
                                Thread.sleep(10000);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                            MatcherAssert.assertThat("", tally_map, notNullValue());
                        };

        List<Thread> threads = new ArrayList<>();

        for (int i = 1; i <= tallierCount; i++) {
            Thread ti_tally = new Thread(tallyRunnable.apply(i));
            threads.add(ti_tally);
        }

        /*
         * Start the threads
         */
        for (Thread thread : threads) {
            thread.start();
        }


        /*
         * Wait for them to finish.
         */
        for (Thread thread : threads) {
            thread.join();
        }

        return res;
    }

    private void voteForYBallots(int numBallots, AthenaFactory factory, Athena athena, int nc, int kappa) throws InterruptedException {


        for (int i = 0; i < numBallots; i++) {
            int randVote = new Random(i).nextInt(nc);
            registerAndVote(randVote, factory, athena, nc, kappa);
        }

        Thread.sleep(numBallots * 1000L);

    }

    private Map<Integer,ElGamalSK> setupForXTalliers(int numberOfTalliers, Athena athena, int nc, int kappa) throws InterruptedException {
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

        List<Thread> threads = new ArrayList<>();
        for (int i = 1; i <= numberOfTalliers; i++) {

            Thread t_i = new Thread(newRunnable.apply(i));
            threads.add(t_i);
        }

        /*
         * Start the threads
         */
        for (Thread thread : threads) {
            thread.start();
        }


        /*
         * Wait for them to finish.
         */
        for (Thread thread : threads) {
            thread.join();
        }

        return talliersSK_HACKY_ASF;
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
