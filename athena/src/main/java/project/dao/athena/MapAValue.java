package project.dao.athena;

import project.dao.mixnet.MixBallot;
import project.elgamal.Ciphertext;

public class MapAValue {
    private final int counter;
    private final Ciphertext homoCombPubCredAndEncNegatedPrivCred;
    private final Ciphertext encryptedVote;


    public MapAValue(int counter, Ciphertext homoCombPubCredAndEncNegatedPrivCred, Ciphertext encryptedVote) {
        this.counter = counter;
        this.homoCombPubCredAndEncNegatedPrivCred = homoCombPubCredAndEncNegatedPrivCred;
        this.encryptedVote = encryptedVote;
    }

    public int getCounter() {
        return counter;
    }

    public Ciphertext getHomoCombPubCredAndEncNegatedPrivCred() {
        return homoCombPubCredAndEncNegatedPrivCred;
    }

    public Ciphertext getEncryptedVote() {
        return encryptedVote;
    }
    
    public MixBallot toMixBallot() {
         return new MixBallot(this.homoCombPubCredAndEncNegatedPrivCred, this.encryptedVote);
        }
    
    
}
