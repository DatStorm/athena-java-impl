package project.elgamal;

import java.math.BigInteger;

public class ElGamalSK {
    private GroupDescription group;
    private BigInteger sk;

    public ElGamalSK(GroupDescription group, BigInteger sk) {
        this.group = group;
        this.sk = sk;
    }

    public BigInteger toBigInteger() {
        return this.sk;
    }

    public ElGamalPK getPK() {
        BigInteger h = group.g.modPow(sk, group.p); // h=g^sk
        return new ElGamalPK(group, h);
    }

    public BigInteger getSK() {
        return sk;
    }
}
