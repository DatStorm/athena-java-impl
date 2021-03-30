package project.dao.bulletproof;

import project.athena.AthenaTally;
import project.athena.AthenaVote;
import project.athena.BulletinBoard;
import project.dao.athena.UVector;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class BulletproofStatement {
    public final Integer n;
    public final BigInteger V; // commitment V = g^m h^\gamma.
    public final ElGamalPK pk;
    public final List<BigInteger> g_vector;
    public final List<BigInteger> h_vector;
    public final UVector uVector;

    protected BulletproofStatement(Builder builder) {
        //Construct Object
        this.n = builder.n;
        this.V = builder.V;
        this.pk = builder.pk;
        this.g_vector = builder.g_vector;
        this.h_vector = builder.h_vector;
        this.uVector = builder.uVector;
    }



    public static class Builder<T extends Builder<T>> {
        private Integer n;
        private BigInteger V; // commitment
        private ElGamalPK pk;
        private List<BigInteger> g_vector;
        private List<BigInteger> h_vector;
        private UVector uVector;

        //Setters
        public T setN(Integer n) {
            this.n = n;
            return (T) this;
        }

        public T setV(BigInteger V) {
            this.V = V;
            return (T) this;
        }

        public T setPK(ElGamalPK pk) {
            this.pk = pk;
            return (T) this;
        }

        public T set_G_Vector(List<BigInteger> g_vector) {
            this.g_vector = g_vector;
            return (T) this;
        }

        public T set_H_Vector(List<BigInteger> h_vector) {
            this.h_vector = h_vector;
            return (T) this;
        }

        public T setUVector(UVector uVector) {
            this.uVector = uVector;
            return (T) this;
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

            return new BulletproofStatement(this);
        }
    }


}
