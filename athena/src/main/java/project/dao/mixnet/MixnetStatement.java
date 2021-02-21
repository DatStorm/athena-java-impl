package project.dao.mixnet;

import project.elgamal.CipherText;

import java.util.List;

public class MixnetStatement {
    private List<MixBallot> listOfB;

    public MixnetStatement(List<MixBallot> bList) {
        this.listOfB = bList;
    }

    public List<MixBallot> getB() {
        return this.listOfB;
    }
}
