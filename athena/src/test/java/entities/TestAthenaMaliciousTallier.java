package entities;

//import org.junit.jupiter.api.*;

import org.junit.Before;
import org.junit.Test;
import project.CONSTANTS;
import project.athena.Athena;
import project.athena.AthenaImpl;
import project.athena.BulletinBoard;
import project.athena.entities.Registrar;
import project.athena.entities.Tallier;
import project.athena.entities.Verifier;
import project.athena.entities.Voter;
import project.factory.AthenaFactory;
import project.factory.MainAthenaFactory;

import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

//@DisplayName("Test Athena Malicious Tallier")
public class TestAthenaMaliciousTallier {
    private int kappa =  CONSTANTS.KAPPA;


    @Before
    public void setUp() {
    }


    /**
     *
     */
    @Test
    public void TestMaliciousTallier() {
        int nc = 10;
        AthenaFactory athenaFactory = new MainAthenaFactory();
        Athena athena = new AthenaImpl(athenaFactory);
        BulletinBoard bb = athenaFactory.getBulletinBoard();

        // Setup the election
        Tallier tallier = new Tallier(athena, bb, kappa, nc);
        tallier.init();
        System.out.println("--> Setup done");


        // Create voters
        int numVoters = 3;
        Voter voter1 = new Voter(athena, bb,kappa);
        Voter voter2 = new Voter(athena, bb,kappa);
        Voter voter3 = new Voter(athena, bb,kappa);
        voter1.init();
        voter2.init();
        voter3.init();

        // Construct and distribute credential to voters
        Registrar registrar = new Registrar(athena, bb, kappa);
        registrar.init();

        registrar.generateCredentials(numVoters);
        voter1.retrieveCredentials(registrar.sendCredentials(0));
        voter2.retrieveCredentials(registrar.sendCredentials(1));
        voter3.retrieveCredentials(registrar.sendCredentials(2));

        // Vote
        voter1.castVote(7);
        voter2.castVote(3);
        voter3.castVote(3);
        System.out.println("--> Voter1, Voter2, Voter3 casted votes");

        //Tally the votes
        System.out.println("--> Tally all votes");
        tallier.tallyVotes();

        // tallyOfVotes deviates and changes the tally posted to the bulletin board.
        Map<Integer, Integer> tallyOfVotes = bb.retrieveTallyOfVotes();
        tallyOfVotes.put(7, tallyOfVotes.get(7) + 1 ); //Add one vote
        tallyOfVotes.put(3, tallyOfVotes.get(3) - 1);  //subtract one vote
        bb.publishTallyOfVotes(tallyOfVotes);

        // Verify tally
        Verifier verifier = new Verifier(athena, bb, kappa);
        verifier.init();
        System.out.println("--> Verify Election");
        boolean success = verifier.verifyElection();

        assertThat("Check tallying went wrong. ", success, is(false));
    }

}
