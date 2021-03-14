package project.athena.entities;


/**
* The role of the Tallier(trusted party) in Athena is the following:
*   - Invoke Setup():
*       - Instantiate ElGamal, generate (pk,sk) + ProveKey, generate (g_vector, h_vector), define (mb, mc, nc).
*       - publish the above to the BulletinBoard.
*
*   - Invoke Tally():
*       - Tally the valid ballots on the BulletinBoard + contruct proofs to prove correct tallying.
**/
public class Tallier {

}
