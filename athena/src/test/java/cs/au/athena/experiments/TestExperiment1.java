package cs.au.athena.experiments;


import cs.au.athena.CONSTANTS;
import cs.au.athena.UTIL;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import cs.au.athena.athena.Athena;
import cs.au.athena.athena.AthenaImpl;
import cs.au.athena.athena.BulletinBoard;
import cs.au.athena.athena.entities.Registrar;
import cs.au.athena.athena.entities.Tallier;
import cs.au.athena.athena.entities.Voter;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.factory.MainAthenaFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class TestExperiment1 {
    Athena athena;
    Registrar registrar;
    Tallier tallier;
    BulletinBoard bb;
    int nc;
    Random random = new Random(CONSTANTS.RANDOM_SEED);
    int kappa = 256;

    ElGamalSK sk;
    ElGamalPK pk;

    long startTime;
    long endTime;


    @BeforeEach
    public void setUp() {
        // Constant group
        // Generate pk,sk
        // Run setup

        AthenaFactory athenaFactory = new MainAthenaFactory();
        athena = new AthenaImpl(athenaFactory);
        bb = athenaFactory.getBulletinBoard();
        nc = 2 ^ 10; // = 1024
        tallier = new Tallier(athena, bb, kappa, nc);
        registrar = new Registrar(athena, bb, kappa);

        startTime = System.nanoTime();

    }


    @AfterEach
    public void tally() {
        tallier.tallyVotes();
        endTime = System.nanoTime();
        UTIL.printEvalMetrics("Athena Tally: ", startTime, endTime);

       PK_Vector pkv = bb.retrievePK_vector();
       boolean succes = athena.Verify(pkv, kappa);
       UTIL.printEvalMetrics("Athena Verify: ", endTime, System.nanoTime());
    }

//    @After
//    public void verify() {
//        PK_Vector pkv = bb.retrievePK_vector();
//        boolean succes = cs.au.athena.athena.Verify(pkv, kappa);
//    }


    @Test
    public void TestExperimentTime1Voters() {
        //Vote 1 times
        int numVoters = 1;
        registerVote(numVoters);

    }

    @Test
    public void TestExperimentTime5Voters() {
        //Vote 5 times
        int numVoters = 5;
        registerVote(numVoters);
    }

    @Test
    public void TestExperimentTime10Voters() {
        //Vote 10 times
        int numVoters = 10;
        registerVote(numVoters);
    }


    @Test
    public void TestExperimentTime20Voters() {
        //Vote 20 times
        int numVoters = 20;
        registerVote(numVoters);
    }




    private void registerVote(int numVoters) {
        tallier.init();
        List<Voter> voters = new ArrayList<>(numVoters);

        // Construct and distribute credential to voters
        registrar.init();
        registrar.generateCredentials(numVoters);

        // Create voters and create their credentials and distributed credentials
        for (int i = 0; i < numVoters; i++) {
            Voter voter = new Voter(athena, bb, kappa);
            voter.init();
            voter.retrieveCredentials(registrar.sendCredentials(i));
            voters.add(voter);
        }

        // Voters cast their vote
        for (Voter voter : voters) {
            int vote = random.nextInt(nc); // cast random vote in [0,nc-1] = [0, nc[
            voter.castVote(vote);
        }
    }
}