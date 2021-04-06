package cs.au.athena.elgamal;

import java.math.BigInteger;

public class ElGamalPK {
    public final Group group;
    public final BigInteger h; //g^sk

    public ElGamalPK(Group group, BigInteger h) {
        this.group = group;
        this.h = h;
    }

    public BigInteger getH() {
        return h;
    }

    public Group getGroup() {
        return this.group;
    }

    @Override
    public String toString() {
        return "pk={\n'h':" + this.h + ",\n " + this.group.toString() + "}";
    }
}
