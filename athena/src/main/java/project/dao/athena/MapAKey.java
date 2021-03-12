package project.dao.athena;

import project.elgamal.CipherText;

import java.math.BigInteger;

public class MapAKey {
    public final CipherText counterBallot;
    public final BigInteger noncedNegatedPrivateCredential;

    public MapAKey(CipherText counterBallot, BigInteger noncedNegatedPrivateCredential) {

        this.counterBallot = counterBallot; // TODO: rename to counterBallot
        this.noncedNegatedPrivateCredential = noncedNegatedPrivateCredential; // TODO: rename to decryptedCombinationEncryptedPrivateCredential
    }
}
