package project.dao.sigma2;

import java.math.BigInteger;

public class ELProof {
    public final BigInteger c;
    public final BigInteger D;
    public final BigInteger D1;
    public final BigInteger D2;

    public ELProof(BigInteger c, BigInteger D, BigInteger D1, BigInteger D2) {
        this.c = c;
        this.D = D;
        this.D1 = D1;
        this.D2 = D2;
    }
}
