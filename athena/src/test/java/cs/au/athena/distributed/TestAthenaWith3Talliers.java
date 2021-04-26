package cs.au.athena.distributed;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.AthenaImpl;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.athena.RegisterStruct;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.MainAthenaFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.sql.Time;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.hamcrest.CoreMatchers.*;


@Tag("TestAthenaWith3Talliers")
@DisplayName("Test Athena with 3 talliers")
public class TestAthenaWith3Talliers {


    @Test
    void TestWith3Talliers() throws InterruptedException{
        int tallierCount = 3;
        int kappa = CONSTANTS.KAPPA;
        int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;

        MainAthenaFactory factory = new MainAthenaFactory(tallierCount, kappa);

        Function<Integer, Runnable> newRunnable =
            (Integer i) ->
                () -> {
                    AthenaImpl athena = new AthenaImpl(factory);
                    int tallierIndex = i;
                    ElGamalSK T_i_sk = athena.Setup(tallierIndex, nc, kappa);

                    try {
                        Thread.sleep(10000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    MatcherAssert.assertThat("", T_i_sk.sk,is(not(BigInteger.ZERO)));

                    RegisterStruct T_i_reg = athena.Register(kappa);
                    MatcherAssert.assertThat("pd != null", T_i_reg.pd, notNullValue());
                    MatcherAssert.assertThat("d != null", T_i_reg.d, notNullValue());

                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                    int voteToCast = tallierIndex * 2;
                    int cnt = 0;

                    Ballot ballot = athena.Vote(T_i_reg.d, voteToCast, cnt, nc, kappa);

                    MatcherAssert.assertThat("b[1]=pubcred != null", ballot.getPublicCredential(), notNullValue());

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
    }
}
