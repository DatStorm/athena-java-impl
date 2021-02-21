package project.dao.mixnet;

import project.elgamal.CipherText;

public class MixBallot {
    private final CipherText c1;
    private final CipherText c_vote;

    public MixBallot(CipherText c1, CipherText c_vote) {
        this.c1 = c1;
        this.c_vote = c_vote;
    }
}
