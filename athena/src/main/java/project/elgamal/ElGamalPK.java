package project.elgamal;

import java.math.BigInteger;

public class ElGamalPK {
    private GroupDescription group;
    private BigInteger h; //g^sk

    public ElGamalPK(GroupDescription group, BigInteger h) {
        this.group = group;
        this.h = h;
    }

    public BigInteger getH() {
        return h;
    }

    public GroupDescription getGroup() {
        return this.group;
    }
}
