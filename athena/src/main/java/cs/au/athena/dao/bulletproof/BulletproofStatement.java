package cs.au.athena.dao.bulletproof;

import cs.au.athena.dao.athena.UVector;
import cs.au.athena.elgamal.ElGamalPK;

import java.math.BigInteger;
import java.util.List;

public class BulletproofStatement {
    public Integer n;
    public BigInteger V; // commitment V = g^m h^\gamma.
    public ElGamalPK pk;
    public List<BigInteger> g_vector;
    public List<BigInteger> h_vector;
    public UVector uVector;

    private BulletproofStatement() { }
    

    public static class Builder {
        private Integer n;
        private BigInteger V; // commitment
        private ElGamalPK pk;
        private List<BigInteger> g_vector;
        private List<BigInteger> h_vector;
        private UVector uVector;

        //Setters
        public Builder setN(Integer n) {
            this.n = n;
            return this;
        }

        public Builder setV(BigInteger V) {
            this.V = V;
            return this;
        }

        public Builder setPK(ElGamalPK pk) {
            this.pk = pk;
            return this;
        }

        public Builder set_G_Vector(List<BigInteger> g_vector) {
            this.g_vector = g_vector;
            return this;
        }

        public Builder set_H_Vector(List<BigInteger> h_vector) {
            this.h_vector = h_vector;
            return this;
        }

        public Builder setUVector(UVector uVector) {
            this.uVector = uVector;
            return this;
        }

        public BulletproofStatement build() {
            //Check that all fields are set
            if (n == null ||
                    V == null ||
                    pk == null ||
                    uVector == null ||
                    g_vector == null ||
                    h_vector == null
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            BulletproofStatement obj = new BulletproofStatement();

            obj.n = this.n;
            obj.V = this.V;
            obj.pk = this.pk;
            obj.g_vector = this.g_vector;
            obj.h_vector = this.h_vector;
            obj.uVector = this.uVector;

            return obj;
        }
    }


}
