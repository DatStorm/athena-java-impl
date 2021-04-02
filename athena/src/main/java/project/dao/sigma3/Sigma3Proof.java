package project.dao.sigma3;


import java.math.BigInteger;

public class Sigma3Proof {
    public final BigInteger a;
    public final BigInteger b;
    public final BigInteger r;

    public Sigma3Proof(BigInteger a, BigInteger b, BigInteger r) {
        this.a = a;
        this.b = b;
        this.r = r;
    }


    @Override
    public String toString() {
        return "\nSigma3Proof{" +
                "a=" + a +
                ", b=" + b +
                ", r=" + r +
                "}\n";
    }

    public boolean isEmpty() {
        // check if the number is bigger then zero
        return this.a.signum() != 1 && this.b.signum() != 1 && this.r.signum() != 1 ;
    }
}