package cs.au.athena.athena.entities;


import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.Athena;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.dao.athena.SK_Vector;
import cs.au.athena.dao.athena.TallyStruct;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;

/**
 * The role of the Tallier(trusted party) in Athena is the following:
 * - Invoke Setup():
 * - Instantiate ElGamal, generate (pk,sk) + ProveKey, generate (g_vector, h_vector), define (mb, mc, nc).
 * - publish the above except sk to the BulletinBoard.
 * <p>
 * - Invoke Tally():
 * - Tally the valid ballots on the BulletinBoard + contruct proofs to prove correct tallying.
 **/
public class Tallier{
    private final int kappa;
    private final Athena athena;
    private final int nc;
    private BulletinBoardV2_0 bb;
    private ElGamalSK sk;
    private ElGamalPK pk;

    public Tallier(Athena athena, BulletinBoardV2_0 bulletinBoard, int kappa,  int nc) {
        this.kappa = kappa;
        this.athena = athena;
        this.bb = bulletinBoard;
        this.nc = nc;
    }


    public void init(int tallierIndex) {
        // Run Setup()
        sk = athena.Setup(tallierIndex, this.nc, this.kappa);
        pk = this.bb.retrievePK_vector().pk;
    }

    public void tallyVotes(int tallierIndex) {
        // Run Tally()
        if (sk == null){
            System.err.println("Tallier.tallyVotes => sk is null! Please run Tallier.init()");
        }
        
        athena.Tally(tallierIndex, sk, nc, this.kappa);
    }

}
