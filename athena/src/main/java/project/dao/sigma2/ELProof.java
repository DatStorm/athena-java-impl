package project.dao.sigma2;

import java.math.BigInteger;

public class ELProof {
    private final BigInteger c;
    private final BigInteger d;
    private final BigInteger d1;
    private final BigInteger d2;

    public ELProof(BigInteger c, BigInteger D, BigInteger D1, BigInteger D2) {
        this.c = c;
        this.d = D;
        this.d1 = D1;
        this.d2 = D2;
    }

    public BigInteger getC() {
        return this.c;
    }
}
