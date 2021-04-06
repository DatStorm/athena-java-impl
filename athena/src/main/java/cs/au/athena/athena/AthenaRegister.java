package cs.au.athena.athena;

import cs.au.athena.UTIL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import cs.au.athena.dao.athena.CredentialTuple;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.athena.RegisterStruct;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.sigma.Sigma1;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.Random;

public class AthenaRegister {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker ATHENA_REGISTER_MARKER = MarkerFactory.getMarker("ATHENA-REGISTER");


    private BulletinBoard bb;
    private Random random;
    private Sigma1 sigma1;
    private ElGamal elGamal;
    private int kappa;


    private AthenaRegister() {}


    public RegisterStruct Register(PK_Vector pkv) {


        if (!AthenaCommon.parsePKV(pkv)) {
            System.err.println("AthenaImpl.Register => ERROR: pkv null");
            return null;
        }

        if (!AthenaCommon.verifyKey(this.sigma1, pkv, this.kappa)) {
            System.err.println("AthenaImpl.Register => ERROR: VerifyKey(...) => false");
            return null;
        }

        BigInteger q = pkv.pk.group.q;

        //Generate nonce. aka private credential
        int n = q.bitLength() - 1;
        BigInteger endRange = BigInteger.TWO.modPow(BigInteger.valueOf(n), q).subtract(BigInteger.ONE); // [0; 2^n-1]
        BigInteger privateCredential = UTIL.getRandomElement(BigInteger.ZERO, endRange, this.random); // a nonce in [0,2^{\lfloor \log_2 q \rfloor} -1]

        // Enc^{exp}_pk(d)  
        Ciphertext publicCredential = this.elGamal.exponentialEncrypt(privateCredential, pkv.pk);

        // bold{d} = (pd, d) = (Enc_pk(g^d), d)
        CredentialTuple credentialTuple = new CredentialTuple(publicCredential, privateCredential);

        this.bb.addPublicCredentitalToL(publicCredential);
        
        return new RegisterStruct(publicCredential, credentialTuple);
    }


    public static class Builder {
        private BulletinBoard bb;
        private Random random;
        private Sigma1 sigma1;
        private ElGamal elGamal;
        private Integer kappa;


        public Builder setBB(BulletinBoard bb) {
            this.bb = bb;
            return this;
        }

        public Builder setRandom(Random random) {
            this.random = random;
            return this;
        }

        public Builder setSigma1(Sigma1 sigma1) {
            this.sigma1 = sigma1;
            return this;
        }

        public Builder setElGamal(ElGamal elgamal) {
            this.elGamal = elgamal;
            return this;
        }

        public Builder setKappa(Integer kappa) {
            this.kappa = kappa;
            return this;
        }



        public AthenaRegister build() {
            //Check that all fields are set
            if (bb == null ||
                random == null ||
                sigma1 == null ||
                kappa == null ||
                elGamal == null

            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }


            //Construct Object
            AthenaRegister obj = new AthenaRegister();

            obj.bb = this.bb;
            obj.random = this.random;
            obj.sigma1 = this.sigma1;
            obj.elGamal = this.elGamal;
            obj.kappa = this.kappa;
            return obj;
        }
    }
}
