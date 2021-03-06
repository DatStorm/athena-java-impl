package cs.au.athena.athena;

import cs.au.athena.GENERATOR;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.VerifyingBB;
import cs.au.athena.athena.distributed.AthenaDistributed;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.factory.AthenaFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import cs.au.athena.dao.athena.CredentialTuple;
import cs.au.athena.dao.athena.RegisterStruct;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.ElGamal;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.Random;

public class AthenaRegister {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("ATHENA-REGISTER");

    private BulletinBoardV2_0 bb;
    private VerifyingBB vbb;
    private Random random;
    private ElGamal elGamal;
    private int kappa;
    private AthenaDistributed distributed;


    private AthenaRegister() {
    }

    public RegisterStruct Register() {
        ElGamalPK pk = this.vbb.retrieveAndVerifyPK();
        BigInteger q = pk.group.q;

        //Generate nonce. aka private credential
        BigInteger privateCredential = GENERATOR.generateUniqueNonce(BigInteger.ZERO, q, this.random);

        // Enc^{exp}_pk(d)
        Ciphertext publicCredential = this.elGamal.exponentialEncrypt(privateCredential, pk);

        // bold{d} = (pd, d) = (Enc_pk(g^d), d)
        CredentialTuple credentialTuple = new CredentialTuple(publicCredential, privateCredential);
        this.bb.addPublicCredentialToL(publicCredential);

        return new RegisterStruct(publicCredential, credentialTuple);
    }


    public static class Builder {
        private AthenaFactory factory;
        private Integer kappa;
        private ElGamal elgamal;


        public Builder setFactory(AthenaFactory factory) {
            this.factory = factory;
            return this;
        }


        public Builder setKappa(Integer kappa) {
            this.kappa = kappa;
            return this;
        }

        public Builder setElGamal(ElGamal elgamal) {
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
            athenaRegister.vbb = this.factory.getVerifyingBulletinBoard();
            athenaRegister.distributed = this.factory.getDistributedAthena();
            athenaRegister.random = this.factory.getRandom();
            athenaRegister.elGamal = this.elgamal;
            athenaRegister.kappa = this.kappa;
            return athenaRegister;
        }
    }
}
