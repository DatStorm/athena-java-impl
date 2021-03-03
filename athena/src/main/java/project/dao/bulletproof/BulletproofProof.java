package project.dao.bulletproof;

import java.math.BigInteger;
import java.util.List;

public class BulletproofProof {
    public final BigInteger a;
    public final BigInteger s;
    public final BigInteger y;
    public final BigInteger z;

    public final BigInteger tau_x;
    public final BigInteger t_hat;
    public final BigInteger mu;
    public final List<BigInteger> l_vector;
    public final List<BigInteger> r_vector;

    private BulletproofProof(BigInteger a, BigInteger s, BigInteger y, BigInteger z, BigInteger tau_x, BigInteger t_hat, BigInteger mu, List<BigInteger> l_vector, List<BigInteger> r_vector) {
        this.a = a;
        this.s = s;
        this.y = y;
        this.z = z;
        this.tau_x = tau_x;
        this.t_hat = t_hat;
        this.mu = mu;
        this.l_vector = l_vector;
        this.r_vector = r_vector;
    }

    public static class Builder {
        public BigInteger a;
        public BigInteger s;
        public BigInteger y;
        public BigInteger z;

        public BigInteger tau_x;
        public BigInteger t_hat;
        public BigInteger mu;
        public List<BigInteger> l_vector;
        public List<BigInteger> r_vector;

        public Builder setAS(BigInteger a, BigInteger s) {
            this.a = a;
            this.s = s;
            return this;
        }

        public Builder setYZ(BigInteger y, BigInteger z) {
            this.y = y;
            this.z = z;
            return this;
        }

        public Builder setTau_x(BigInteger tau_x) {
            this.tau_x = tau_x;
            return this;
        }

        public Builder setT_hat(BigInteger t_hat) {
            this.t_hat = t_hat;
            return this;
        }

        public Builder setMu(BigInteger mu) {
            this.mu = mu;
            return this;
        }

        public Builder setL_vector(List<BigInteger> l_vector) {
            this.l_vector = l_vector;
            return this;
        }

        public Builder setR_vector(List<BigInteger> r_vector) {
            this.r_vector = r_vector;
            return this;
        }

        public BulletproofProof build() {
            if (a == null ||
                s == null ||
                y == null ||
                z == null ||
                tau_x == null ||
                t_hat == null ||
                mu == null ||
                l_vector == null || 
                r_vector == null)
            {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            return new BulletproofProof(a, s, y, z, tau_x, t_hat, mu, l_vector, r_vector);
        }
    }
}
