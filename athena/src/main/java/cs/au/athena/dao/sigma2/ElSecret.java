package cs.au.athena.dao.sigma2;

import java.math.BigInteger;

public class ElSecret {
    public final BigInteger x;
    public final BigInteger r1;
    public final BigInteger r2;

    public ElSecret(BigInteger x, BigInteger r1, BigInteger r2) {
        this.x = x;
        this.r1 = r1;
        this.r2 = r2;
    }

    /*
    public Builder builder() {
        return new Builder();
    }

    public static class Builder() {
        public final BigInteger x;
        public final BigInteger r1;
        public final BigInteger r2;

        public ElSecretBuilder setX(BigInteger x) {
            this.x = x;
            return this;
        }
        public ElSecretBuilder setR1(BigInteger r1) {
            this.r1 = r1;
            return this;
        }
        public ElSecretBuilder setR2(BigInteger r2) {
            this.r2= r2;
            return this;
        }
        public ElSecret build() {
            return new ElSecret(x,r1,r2);
        }
}

 */
}

