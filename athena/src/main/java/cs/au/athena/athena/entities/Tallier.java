package cs.au.athena.athena.entities;


import cs.au.athena.athena.Athena;
import cs.au.athena.athena.BulletinBoard;
import cs.au.athena.dao.athena.SK_Vector;
import cs.au.athena.dao.athena.ElectionSetup;
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
public class Tallier implements Entity {
    private final int kappa;
    private final Athena athena;
    private final int nc;
    private BulletinBoard bulletinBoard;

    private ElectionSetup electionSetup;
    private ElGamalPK pk;
    private ElGamalSK sk;

    public Tallier(Athena athena, BulletinBoard bulletinBoard, int kappa,  int nc) {
        this.kappa = kappa;
        this.athena = athena;
        this.bulletinBoard = bulletinBoard;
        this.nc = nc;
    }


    public void init() {
        // Run Setup()
        electionSetup = athena.Setup(this.nc,this.kappa);
        sk = electionSetup.sk;
        pk = this.bulletinBoard.retrievePK_vector().pk;
    }

    public void tallyVotes() {
        // Run Tally()
        if (sk == null){
            System.err.println("Tallier.tallyVotes => sk is null! Please run Tallier.init()");
        }
        
        TallyStruct tallyStruct = athena.Tally(new SK_Vector(sk), nc, this.kappa);
    }

}