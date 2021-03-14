package project.dao.mixnet;

import com.google.common.primitives.Bytes;
import project.elgamal.Ciphertext;

import java.math.BigInteger;
import java.util.Objects;

public class MixBallot {
    private final Ciphertext c1;
    private final Ciphertext c2;

    public MixBallot(Ciphertext c1, Ciphertext c2) {
        this.c1 = c1;
        this.c2 = c2;
    }

    public byte[] toByteArray() {
        byte[] c1_c1 = this.c1.c1.toByteArray();
        byte[] c1_c2 = this.c1.c2.toByteArray();
        byte[] cv_c1 = this.c2.c1.toByteArray();
        byte[] cv_c2 = this.c2.c2.toByteArray();
        return Bytes.concat(c1_c1, c1_c2, cv_c1, cv_c2);
    }

    public MixBallot multiply(MixBallot ballot, BigInteger q) {
        Ciphertext c1_mult = this.c1.multiply(ballot.c1, q);
        Ciphertext c2_vote = this.c2.multiply(ballot.c2, q);
        return new MixBallot(c1_mult,c2_vote);
    }


    public Ciphertext getC1() {
        return c1;
    }

    public Ciphertext getC2() {
        return c2;
    }

    @Override
    public String toString() {
        return "MixBallot{" +
                "c1=" + c1.toString() +
                ", c2=" + c2.toString() +
                '}';
    }

    public String toShortString() {
        return "MB{" +
                "c1=" + c1.toShortString() +
                ", c2=" + c2.toShortString() +
                '}';
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MixBallot mixBallot = (MixBallot) o;
        return Objects.equals(c1, mixBallot.c1) && Objects.equals(c2, mixBallot.c2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(c1, c2);
    }
}
