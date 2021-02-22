package project.dao;

import project.elgamal.ElGamalSK;

public class PK_SK_FRAKM {
    public final ElGamalSK sk;
    public final MessageSpace messageSpace;

    public PK_SK_FRAKM(ElGamalSK sk, MessageSpace messageSpace) {
        this.sk = sk;
        this.messageSpace = messageSpace;
    }

    public ElGamalSK getSK() {
        return this.sk;
    }

    public MessageSpace getMessageSpace() {
        return this.messageSpace;
    }
}
