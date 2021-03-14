package manual;

import project.CONSTANTS;
import project.athena.Athena;
import project.athena.AthenaImpl;
import project.athena.BulletinBoard;
import project.athena.entities.*;
import project.factory.AthenaFactory;
import project.factory.MainAthenaFactory;

public class ManualTestAthenaTallier {

    private static int kappa = CONSTANTS.KAPPA;

    public static void main(String[] args) {
        int nc = 10;


        AthenaFactory athenaFactory = new MainAthenaFactory();
        Athena athena = new AthenaImpl(athenaFactory);
        BulletinBoard bb = athenaFactory.getBulletinBoard();

        // Setup the election
        Tallier tallier = new Tallier(athena, bb, kappa, nc);
        tallier.init();

        // Create voters
        int numVoters = 2;
        Voter voter1 = new Voter(athena, bb);
        Voter voter2 = new Voter(athena, bb);
        voter1.init();
        voter2.init();

        // Construct and distribute credential to voters
        Registrar registrar = new Registrar(athena, bb);
        registrar.init();

        registrar.generateCredentials(numVoters);
        voter1.retrieveCredentials(registrar.sendCredentials(0));
        voter2.retrieveCredentials(registrar.sendCredentials(1));

        // Vote
        voter1.castVote(7);
        voter2.castVote(3);

        //Tally the votes
        tallier.tallyVotes();

        // Verify tally
        Verifier verifier = new Verifier(athena, bb);
        verifier.init();
        boolean success = verifier.verifyElection();

        System.out.println("DOES WE SUCCED? " + (success ? "YES" : "NO"));
    }
}
