package cs.au.athena.dao.athena;

import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.elgamal.Ciphertext;

public class MapAValue {
    private final int counter;
    private final Ciphertext combinedCredential; 
    private final Ciphertext encryptedVote;


    public MapAValue(int counter, Ciphertext combinedCredential, Ciphertext encryptedVote) {
        this.counter = counter;
        this.combinedCredential = combinedCredential;
        this.encryptedVote = encryptedVote;
    }

    public int getCounter() {
        return counter;
    }

    public Ciphertext getCombinedCredential() {
        return combinedCredential;
    }

    public Ciphertext getEncryptedVote() {
        return encryptedVote;
    }

    /**
     * Throws away the counter not needed from now on.
     * @return
     */
    public MixBallot toMixBallot() {
        return new MixBallot(this.combinedCredential, this.encryptedVote);
    }

    public String toLongString() {
        return "MapAValue{" +
                "counter=" + counter +
                ", homoCombPubCredAndEncNegatedPrivCred=" + combinedCredential +
                ", encryptedVote=" + encryptedVote +
                '}';
    }

    @Override
    public String toString() {
        return "A.Val:{" +
                "cnt" + counter +
                CONSTANTS.ANSI_YELLOW + ", homoCombPubCredAndEncNegatedPrivCred=" + combinedCredential.toShortString() + CONSTANTS.ANSI_RESET +
                ", encVote=" + encryptedVote.toShortString() +
                '}';
    }
}
