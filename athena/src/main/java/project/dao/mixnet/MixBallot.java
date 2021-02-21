package project.dao.mixnet;

import com.google.common.primitives.Bytes;
import project.elgamal.CipherText;

public class MixBallot {
    private final CipherText c1;
    private final CipherText c_vote;

    public MixBallot(CipherText c1, CipherText c_vote) {
        this.c1 = c1;
        this.c_vote = c_vote;
    }

    public byte[] toByteArray() {
        byte[] c1_c1 = this.c1.c1.toByteArray();
        byte[] c1_c2 = this.c1.c2.toByteArray();
        byte[] cv_c1 = this.c_vote.c1.toByteArray();
        byte[] cv_c2 = this.c_vote.c2.toByteArray();
        return Bytes.concat(c1_c1, c1_c2, cv_c1, cv_c2);
    }

    public MixBallot multiply(MixBallot ballot) {
        CipherText c1_mult = this.c1.multiply(ballot.c1);
        CipherText c2_vote = this.c_vote.multiply(ballot.c_vote);
        return new MixBallot(c1_mult,c2_vote);
    }


    public CipherText getC1() {
        return c1;
    }

    public CipherText getC_vote() {
        return c_vote;
    }
    public CipherText getC2() {
        return c_vote;
    }
}
