package project.dao.sigma2;

import java.math.BigInteger;

public class Sigma2Proof {
    public final ELStatement statementEL_0;
    public final SQRStatement statementSQR_1;
    public final SQRStatement statementSQR_2;
    public final ELProof proofEL_0;
    public final SQRProof proofSQR_1;
    public final SQRProof proofSQR_2;
    public final BigInteger c1;
    public final BigInteger c2;
    public final BigInteger c_prime_prime;
    public final BigInteger c_prime_1;
    public final BigInteger c_prime_2;
    public final BigInteger c_prime_3;
    public final BigInteger s;
    public final BigInteger t;
    public final BigInteger x;
    public final BigInteger y;
    public final BigInteger u;
    public final BigInteger v;

    public Sigma2Proof(ELStatement statementEL_0,
                       SQRStatement statementSQR_1,
                       SQRStatement statementSQR_2,
                       ELProof proofEL_0,
                       SQRProof proofSQR_1,
                       SQRProof proofSQR_2,
                       BigInteger c1,
                       BigInteger c2,
                       BigInteger c_prime_prime,
                       BigInteger c_prime_1,
                       BigInteger c_prime_2,
                       BigInteger c_prime_3,
                       BigInteger s,
                       BigInteger t,
                       BigInteger x,
                       BigInteger y,
                       BigInteger u,
                       BigInteger v) {

        this.statementEL_0 = statementEL_0;
        this.statementSQR_1 = statementSQR_1;
        this.statementSQR_2 = statementSQR_2;
        this.proofEL_0 = proofEL_0;
        this.proofSQR_1 = proofSQR_1;
        this.proofSQR_2 = proofSQR_2;
        this.c1 = c1;
        this.c2 = c2;
        this.c_prime_prime = c_prime_prime;
        this.c_prime_1 = c_prime_1;
        this.c_prime_2 = c_prime_2;
        this.c_prime_3 = c_prime_3;
        this.s = s;
        this.t = t;
        this.x = x;
        this.y = y;
        this.u = u;
        this.v = v;
    }
}
