package cs.au.athena.dao.athena;

import cs.au.athena.elgamal.Ciphertext;

import java.math.BigInteger;
import java.util.Objects;

public class MapAKey {
    public final Ciphertext counterBallot;
    public final BigInteger noncedNegatedPrivateCredential;

    public MapAKey(Ciphertext counterBallot, BigInteger noncedNegatedPrivateCredential) {

        this.counterBallot = counterBallot; 
        this.noncedNegatedPrivateCredential = noncedNegatedPrivateCredential; 
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MapAKey mapAKey = (MapAKey) o;
        return Objects.equals(counterBallot, mapAKey.counterBallot) && Objects.equals(noncedNegatedPrivateCredential, mapAKey.noncedNegatedPrivateCredential);
    }

    @Override
    public int hashCode() {
        return Objects.hash(counterBallot, noncedNegatedPrivateCredential);
    }
}
