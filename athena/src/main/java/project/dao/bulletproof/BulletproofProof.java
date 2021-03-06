package project.dao.bulletproof;

import java.math.BigInteger;
import java.util.List;

public class BulletproofProof {
    public final BigInteger a;
    public final BigInteger s;
    public final BigInteger y;
    public final BigInteger z;
    public final BigInteger T_1;
    public final BigInteger T_2;
    public final BigInteger x;

    public final BigInteger tau_x;
    public final BigInteger t_hat;
    public final BigInteger mu;
    public final List<BigInteger> l_vector;
    public final List<BigInteger> r_vector;
    public final List<BigInteger> g_vector;
    public final List<BigInteger> h_vector;

    // a, s, y, z, T_1, T_2, x, tau_x, t_hat, mu, l_vector, r_vector, g_vector, h_vector
    private BulletproofProof(BigInteger a,
                             BigInteger s,
                             BigInteger y,
                             BigInteger z,
                             BigInteger T_1,
                             BigInteger T_2,
                             BigInteger x,
                             BigInteger tau_x,
                             BigInteger t_hat,
                             BigInteger mu,
                             List<BigInteger> l_vector,
                             List<BigInteger> r_vector,
                             List<BigInteger> g_vector,
                             List<BigInteger> h_vector) {
        this.a = a;
        this.s = s;
        this.y = y;
        this.z = z;
        this.T_1 = T_1;
        this.T_2 = T_2;
        this.x = x;
        this.tau_x = tau_x;
        this.t_hat = t_hat;
        this.mu = mu;
        this.l_vector = l_vector;
        this.r_vector = r_vector;
        this.g_vector = g_vector;
        this.h_vector = h_vector;
    }

    public static class Builder {
        private BigInteger a;
        private BigInteger s;
        private BigInteger y;
        private BigInteger z;
        private BigInteger T_1;
        private BigInteger T_2;
        private BigInteger x;

        private BigInteger tau_x;
        private BigInteger t_hat;
        private BigInteger mu;
        private List<BigInteger> l_vector;
        private List<BigInteger> r_vector;
        private List<BigInteger> g_vector;
        private List<BigInteger> h_vector;

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

        public Builder setT1_T2(BigInteger T_1, BigInteger T_2) {
            this.T_1 = T_1;
            this.T_2 = T_2;
            return this;
        }

        public Builder setX(BigInteger x) {
            this.x = x;
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

        public Builder setG_vector(List<BigInteger> g_vector) {
            this.g_vector = g_vector;
            return this;
        }

        public Builder setH_vector(List<BigInteger> h_vector) {
            this.h_vector = h_vector;
            return this;
        }

        public BulletproofProof build() {
            //Check that all fields are set
            if (a == null ||
                    s == null ||
                    y == null ||
                    z == null ||
                    T_1 == null ||
                    T_2 == null ||
                    x == null ||
                    tau_x == null ||
                    t_hat == null ||
                    mu == null ||
                    l_vector == null ||
                    r_vector == null ||
                    g_vector == null ||
                    h_vector == null) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            return new BulletproofProof(a, s, y, z, T_1, T_2, x, tau_x, t_hat, mu, l_vector, r_vector, g_vector, h_vector);
        }
    }
}
