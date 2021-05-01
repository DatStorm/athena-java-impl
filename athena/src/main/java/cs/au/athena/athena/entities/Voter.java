package cs.au.athena.athena.entities;


import cs.au.athena.athena.Athena;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.VerifyingBulletinBoardV2_0;
import cs.au.athena.dao.athena.Ballot;
import cs.au.athena.dao.athena.CredentialTuple;
import cs.au.athena.elgamal.ElGamalPK;


/**
 * The role of the Voter in Athena is the following:
 * - Fetch credentials from the Registrar.
 * - Fetch pk and (g_vector, h_vector) from the BulletinBoard.
 * - Invoke Vote():
 * - Create ballot and publish this to BulletinBoard.
 **/
public class Voter {
    private final Athena athena;
    private final BulletinBoardV2_0 bb;
    private final VerifyingBulletinBoardV2_0 vbb;
    private final int kappa;
    private CredentialTuple credentialTuple;
    private int nc;
    private int counter;
    private ElGamalPK pk;

    public Voter(Athena athena, BulletinBoardV2_0 bulletinBoard, int kappa) {
        this.athena = athena;
        this.bb = bulletinBoard;
        this.vbb = new VerifyingBulletinBoardV2_0(bb);
        this.kappa = kappa;
    }


    public void init() {
        // Fetch pk, nc and g_vector and h_vector from bulletin board
        pk = vbb.retrieveAndVerifyPK();
        nc = bb.retrieveNumberOfCandidates();
        counter = 0; // TODO: use a timestamp perhaps
    }

    // Fetch credentials from Registrar
    public void retrieveCredentials(CredentialTuple credentialTuple) {
        this.credentialTuple = credentialTuple;
    }

    // Cast vote
    public void castVote(int vote) {
        if (pk == null) {
            System.err.println("Voter.castVote => pk is null! Please run Voter.init()");
             return;
        }
        if (vote > nc) {
            System.err.println("Voter.castVote => vote > nc! Please fix.");
            return;
        }

        counter = counter + 1;
        Ballot ballot = athena.Vote(credentialTuple, vote, counter, nc, kappa);

         // publish the ballot
         bb.publishBallot(ballot);
    }
}
