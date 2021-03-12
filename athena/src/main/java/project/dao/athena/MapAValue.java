package project.dao.athena;

import project.dao.mixnet.MixBallot;
import project.elgamal.CipherText;

public class MapAValue {
    private final int counter;
    private final CipherText homoCombPubCredAndEncNegatedPrivCred;
    private final CipherText encryptedVote;


    public MapAValue(int counter, CipherText homoCombPubCredAndEncNegatedPrivCred, CipherText encryptedVote) {
        this.counter = counter;
        this.homoCombPubCredAndEncNegatedPrivCred = homoCombPubCredAndEncNegatedPrivCred;
        this.encryptedVote = encryptedVote;
    }

    public int getCounter() {
        return counter;
    }

    public CipherText getHomoCombPubCredAndEncNegatedPrivCred() {
        return homoCombPubCredAndEncNegatedPrivCred;
    }

    public CipherText getEncryptedVote() {
        return encryptedVote;
    }
    
    public MixBallot toMixBallot() {
         return new MixBallot(this.homoCombPubCredAndEncNegatedPrivCred, this.encryptedVote);
        }
    
    
}
