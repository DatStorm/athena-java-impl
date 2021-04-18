package cs.au.athena.entities;

//import org.junit.jupiter.api.*;

import cs.au.athena.CONSTANTS;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import cs.au.athena.athena.Athena;
import cs.au.athena.athena.AthenaImpl;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.entities.Registrar;
import cs.au.athena.athena.entities.Tallier;
import cs.au.athena.athena.entities.Verifier;
import cs.au.athena.athena.entities.Voter;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.factory.MainAthenaFactory;

import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

//@DisplayName("Test Athena Malicious Tallier")
@Tag("TestAthenaMaliciousTallier")
@DisplayName("Test Athena Malicious Tallier")
public class TestAthenaMaliciousTallier {
    private int kappa =  CONSTANTS.KAPPA;


    @BeforeEach
    public void setUp() {
    }


    /**
     *
     */
    @Test
    public void TestMaliciousTallier() {
        int nc = 10;
        AthenaFactory athenaFactory = new MainAthenaFactory(AthenaFactory.STRATEGY.SINGLE);
        Athena athena = new AthenaImpl(athenaFactory);
//        BulletinBoard bb = athenaFactory.getBulletinBoard();
        BulletinBoard bb = BulletinBoard.getInstance(); // TODO: RePLACE WITH ABOVE WHEN BB IS DONE!

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
