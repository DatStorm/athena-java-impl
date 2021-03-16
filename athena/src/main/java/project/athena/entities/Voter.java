package project.athena.entities;


import project.athena.Athena;
import project.athena.BulletinBoard;
import project.dao.athena.Ballot;
import project.dao.athena.CredentialTuple;
import project.dao.athena.PK_Vector;


/**
 * The role of the Voter in Athena is the following:
 * - Fetch credentials from the Registrar.
 * - Fetch pk and (g_vector, h_vector) from the BulletinBoard.
 * - Invoke Vote():
 * - Create ballot and publish this to BulletinBoard.
 **/
public class Voter implements Entity {
    private final Athena athena;
    private final BulletinBoard bulletinBoard;
    private CredentialTuple credentialTuple;
    private PK_Vector pk_vector;
    private int nc;
    private int counter;

    public Voter(Athena athena, BulletinBoard bulletinBoard) {
        this.athena = athena;
        this.bulletinBoard = bulletinBoard;
    }


    public void init() {
        // Fetch pk and nc from bulletin board
        pk_vector = bulletinBoard.retrievePK_vector();
        nc = bulletinBoard.retrieveNumberOfCandidates();
        counter = 0;
    }

    // Fetch credentials from Registrar
    public void retrieveCredentials(CredentialTuple credentialTuple) {
        this.credentialTuple = credentialTuple;
    }

    // Cast vote
    public void castVote(int vote) {
//     public Ballot castVote(int vote) {
        if (pk_vector == null) {
            System.err.println("Voter.castVote => pkVector is null! Please run Voter.init()");
             return;
        }

        if (vote > nc) {
            System.err.println("Voter.castVote => vote > nc! Please fix.");
            return;
        }

        counter = counter + 1;
        Ballot ballot = athena.Vote(credentialTuple, pk_vector, vote, counter, nc);
//         return ballot;
    }
}
