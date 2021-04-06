package cs.au.athena.dao.athena;

import cs.au.athena.elgamal.Ciphertext;

import java.math.BigInteger;

public class MapAKey {
    public final Ciphertext counterBallot;
    public final BigInteger noncedNegatedPrivateCredential;

    public MapAKey(Ciphertext counterBallot, BigInteger noncedNegatedPrivateCredential) {

        this.counterBallot = counterBallot; 
        this.noncedNegatedPrivateCredential = noncedNegatedPrivateCredential; 
    }
}
