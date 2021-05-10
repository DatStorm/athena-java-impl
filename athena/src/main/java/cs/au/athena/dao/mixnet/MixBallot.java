package cs.au.athena.dao.mixnet;

import com.google.common.primitives.Bytes;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.Group;

import java.io.Serializable;
import java.util.Objects;

public class MixBallot implements Serializable {
    private final Ciphertext combinedCredential;    
    private final Ciphertext encryptedVote;    

    public MixBallot(Ciphertext combinedCredential, Ciphertext encryptedVote) {
        this.combinedCredential = combinedCredential;
        this.encryptedVote = encryptedVote;
    }

    public byte[] toByteArray() {
        byte[] c1_c1 = this.combinedCredential.c1.toByteArray();
        byte[] c1_c2 = this.combinedCredential.c2.toByteArray();
        byte[] cv_c1 = this.encryptedVote.c1.toByteArray();
        byte[] cv_c2 = this.encryptedVote.c2.toByteArray();
        return Bytes.concat(c1_c1, c1_c2, cv_c1, cv_c2);
    }

    public MixBallot multiply(MixBallot ballot, Group group) {
        Ciphertext c1_mult = this.combinedCredential.multiply(ballot.combinedCredential, group);
        Ciphertext c2_vote = this.encryptedVote.multiply(ballot.encryptedVote, group);
        return new MixBallot(c1_mult, c2_vote);
    }


    public Ciphertext getCombinedCredential() {
        return combinedCredential;
    }

    public Ciphertext getEncryptedVote() {
        return encryptedVote;
    }

    @Override
    public String toString() {
        return "MixBallot{" +
                "c1=" + combinedCredential.toString() +
                ", c2=" + encryptedVote.toString() +
                '}';
    }

    public String toShortString() {
        return "MB{" +
                "c1=" + combinedCredential.toShortString() +
                ", c2=" + encryptedVote.toShortString() +
                '}';
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MixBallot mixBallot = (MixBallot) o;
        return Objects.equals(combinedCredential, mixBallot.combinedCredential) && Objects.equals(encryptedVote, mixBallot.encryptedVote);
    }

    @Override
    public int hashCode() {
        return Objects.hash(combinedCredential, encryptedVote);
    }
}
