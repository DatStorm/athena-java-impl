package project.athena;

import project.CONSTANTS;
import project.UTIL;
import project.dao.athena.CredentialTuple;
import project.dao.athena.PK_Vector;
import project.dao.athena.RegisterStruct;
import project.elgamal.Ciphertext;
import project.elgamal.ElGamal;
import project.sigma.Sigma1;

import java.math.BigInteger;
import java.util.Random;

public class AthenaRegister {
    private static final int kappa = CONSTANTS.KAPPA;
    private final BulletinBoard bb;
    private final Random random;
    private final Sigma1 sigma1;
    private final ElGamal elGamal;


    private AthenaRegister(BulletinBoard bb, Random random, Sigma1 sigma1, ElGamal elGamal) {
        this.bb = bb;
        this.random = random;
        this.sigma1 = sigma1;
        this.elGamal = elGamal;
    }


    public RegisterStruct Register(PK_Vector pkv) {
        if (!AthenaCommon.parsePKV(pkv)) {
            System.err.println("AthenaImpl.Register => ERROR: pkv null");
            return null;
        }

        if (!AthenaCommon.verifyKey(sigma1, pkv, kappa)) {
            System.err.println("AthenaImpl.Register => ERROR: VerifyKey(...) => false");
            return null;
        }

        BigInteger q = pkv.pk.group.q;

        //Generate nonce. aka private credential
        BigInteger privateCredential = UTIL.getRandomElement(BigInteger.ONE, q, random);
        Ciphertext publicCredential = elGamal.encrypt(privateCredential, pkv.pk);

        // bold{d} = (pd, d) = (Enc_pk(g^d), d)
        CredentialTuple credentialTuple = new CredentialTuple(publicCredential, privateCredential);


        bb.addPublicCredentitalToL(publicCredential);
        return new RegisterStruct(publicCredential, credentialTuple);
    }



    public static class Builder {
        private BulletinBoard bb;
        private Random random;
        private Sigma1 sigma1;
        private ElGamal elgamal;


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
            this.elgamal = elgamal;
            return this;
        }



        public AthenaRegister build() {
            //Check that all fields are set
            if (
                    bb == null ||
                    random == null ||
                    sigma1 == null ||
                    elgamal == null

            ) {
                throw new IllegalArgumentException("Not all fields have been set");
            }

            //Construct Object
            return new AthenaRegister(bb, random, sigma1, elgamal);
        }
    }
}
