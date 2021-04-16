package cs.au.athena.athena;

import cs.au.athena.GENERATOR;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.strategy.Strategy;
import cs.au.athena.factory.AthenaFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import cs.au.athena.dao.athena.CredentialTuple;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.athena.RegisterStruct;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.Elgamal;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.Random;

public class AthenaRegister {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker ATHENA_REGISTER_MARKER = MarkerFactory.getMarker("ATHENA-REGISTER");

    private BulletinBoard bb;
    private Random random;
    private Elgamal elGamal;
    private int kappa;
    private Strategy strategy;


    private AthenaRegister() {
    }

    public RegisterStruct Register(PK_Vector pkv) {
        if (!AthenaCommon.parsePKV(pkv)) {
            System.err.println("AthenaRegister.Register => ERROR: pkv null");
            return null;
        }

        if (!this.strategy.verifyKey(pkv.pk, pkv.rho, this.kappa)) {
            System.err.println("AthenaRegister.Register => ERROR: VerifyKey(...) => false");
            return null;
        }

        BigInteger q = pkv.pk.group.q;

        //Generate nonce. aka private credential
        BigInteger privateCredential = GENERATOR.generateUniqueNonce(BigInteger.ZERO, q, this.random); // a nonce in [0,q]

        // Enc^{exp}_pk(d)  
        Ciphertext publicCredential = this.elGamal.exponentialEncrypt(privateCredential, pkv.pk);

        // bold{d} = (pd, d) = (Enc_pk(g^d), d)
        CredentialTuple credentialTuple = new CredentialTuple(publicCredential, privateCredential);
        this.bb.addPublicCredentialToL(publicCredential);

        return new RegisterStruct(publicCredential, credentialTuple);
    }


    public static class Builder {
        private AthenaFactory factory;
        private Integer kappa;
        private Elgamal elgamal;


        public Builder setFactory(AthenaFactory factory) {
            this.factory = factory;
            return this;
        }


        public Builder setKappa(Integer kappa) {
            this.kappa = kappa;
            return this;
        }

        public Builder setElGamal(Elgamal elgamal) {
            this.elgamal = elgamal;
            return this;
        }


        public AthenaRegister build() {
            //Check that all fields are set
            if (factory == null ||
                    elgamal == null ||
                    kappa == null
            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }


            //Construct Object
            AthenaRegister athenaRegister = new AthenaRegister();
            athenaRegister.bb = this.factory.getBulletinBoard();
            athenaRegister.strategy = this.factory.getStrategy();
            athenaRegister.random = this.factory.getRandom();
            athenaRegister.elGamal = this.elgamal;
            athenaRegister.kappa = this.kappa;
            return athenaRegister;
        }
    }
}
