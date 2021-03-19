package manual;

import project.CONSTANTS;
import project.UTIL;
import project.athena.Athena;
import project.athena.AthenaImpl;
import project.athena.BulletinBoard;
import project.athena.entities.Registrar;
import project.athena.entities.Tallier;
import project.athena.entities.Verifier;
import project.athena.entities.Voter;
import project.dao.athena.CredentialTuple;
import project.factory.AthenaFactory;
import project.factory.MainAthenaFactory;

import java.math.BigInteger;

public class ManualTestAthenaTallierEvilVoter {
    private static int kappa = CONSTANTS.KAPPA;


    // We emulate an attack from
    public static void main(String[] args) {
        int nc = 10;


        // Vote
        int vote1 = 4;
        int vote2 = 2;
        int voteEvil = 2;

        // Create voters
        int numVoters = 2; // we only have 2 real voter


        AthenaFactory athenaFactory = new MainAthenaFactory();
        Athena athena = new AthenaImpl(athenaFactory);
        BulletinBoard bb = athenaFactory.getBulletinBoard();

        // Setup the election
        Tallier tallier = new Tallier(athena, bb, kappa, nc);
        tallier.init();
        System.out.println("--> Setup done");


        Voter voter1 = new Voter(athena, bb);
        Voter voter2 = new Voter(athena, bb);
        Voter voterEvil = new Voter(athena, bb);
        voter1.init();
        voter2.init();
        voterEvil.init();

        // Construct and distribute credential to voters
        Registrar registrar = new Registrar(athena, bb);
        registrar.init();

        registrar.generateCredentials(numVoters);
        voter1.retrieveCredentials(registrar.sendCredentials(0));
        voter2.retrieveCredentials(registrar.sendCredentials(1));

        //Malious voter steals public credential of voter2
        BigInteger q = bb.retrievePK_vector().pk.getGroup().getQ();
        int n = q.bitLength() - 1;
        BigInteger endRange = BigInteger.TWO.modPow(BigInteger.valueOf(n), q).subtract(BigInteger.ONE); // [0; 2^n-1]
        BigInteger fakedPrivCred = UTIL.getRandomElement(BigInteger.ZERO, endRange, athenaFactory.getRandom()); // a nonce in [0,2^{\lfloor \log_2 q \rfloor} -1]

        CredentialTuple fakedCredential = new CredentialTuple(registrar.sendCredentials(1).publicCredential, fakedPrivCred);
        voterEvil.retrieveCredentials(fakedCredential);

        voter1.castVote(vote1);
        voter2.castVote(vote2);
        voterEvil.castVote(voteEvil);
        System.out.println("--> Voter1, Voter2, VoterEvil casted votes");

        //Tally the votes
        System.out.println("--> Tally all votes");
        tallier.tallyVotes();

        // Verify tally
        Verifier verifier = new Verifier(athena, bb);
        verifier.init();
        System.out.println("--> Verify Election:");

        boolean succeeds = verifier.verifyElection();
        System.out.println("Did we successfully avoid counting the Evil Vote?: " + (succeeds ?  "Yes" : "No"));
    }
}
