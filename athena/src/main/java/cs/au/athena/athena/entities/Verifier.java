package cs.au.athena.athena.entities;


import cs.au.athena.athena.Athena;
import cs.au.athena.athena.BulletinBoard;
import cs.au.athena.dao.athena.PFStruct;
import cs.au.athena.dao.athena.PK_Vector;

import java.util.Map;

/**
 * The role of the Verifier(anyone) in Athena is the following:
 * - Invoke Verify():
 * - Check the proofs constructed by the Tallier to check that the tallying is done correctly.
 **/
public class Verifier implements Entity {
    private BulletinBoard bulletinBoard;
    private Athena athena;
    private PK_Vector pk_vector;
    private PFStruct pf;
    private int nc;
    private Map<Integer, Integer> tally;
    private int kappa;

    public Verifier(Athena athena, BulletinBoard bulletinBoard, int kappa) {
        this.athena = athena;
        this.bulletinBoard = bulletinBoard;
        this.kappa = kappa;
    }


    public void init() {
        // Fetch nc, pk, pf=(pfr, mixBallots, pfd), ballots and mixBallots from bulletin board
        pk_vector = bulletinBoard.retrievePK_vector();
    }

    public boolean verifyElection(){
        if (pk_vector == null){
            System.err.println("Verifier.verifyElection => pk_vector is null! Please run Verifier.init()");
            return false;
        }

        boolean success = athena.Verify(pk_vector, kappa);
        return success;
    }
}
