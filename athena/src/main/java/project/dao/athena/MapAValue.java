package project.dao.athena;

import project.dao.mixnet.MixBallot;
import project.elgamal.Ciphertext;

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

    @Override
    public String toString() {
        return "MapAValue{" +
                "counter=" + counter +
                ", homoCombPubCredAndEncNegatedPrivCred=" + combinedCredential +
                ", encryptedVote=" + encryptedVote +
                '}';
    }
}
