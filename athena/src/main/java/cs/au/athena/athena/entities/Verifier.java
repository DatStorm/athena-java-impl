package cs.au.athena.athena.entities;


import cs.au.athena.athena.Athena;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.dao.athena.PFStruct;
import cs.au.athena.dao.athena.PK_Vector;

import java.util.Map;

/**
 * The role of the Verifier(anyone) in Athena is the following:
 * - Invoke Verify():
 * - Check the proofs constructed by the Tallier to check that the tallying is done correctly.
 **/
public class Verifier {
    private BulletinBoardV2_0 bb;
    private Athena athena;
    private PK_Vector pk_vector;
    private PFStruct pf;
    private int nc;
    private Map<Integer, Integer> tally;
    private int kappa;

    public Verifier(Athena athena, BulletinBoardV2_0 bulletinBoard, int kappa) {
        this.athena = athena;
        this.bb = bulletinBoard;
        this.kappa = kappa;
    }


    public void init() {
    }

    public boolean verifyElection(){
        return athena.Verify(kappa);
    }
}
