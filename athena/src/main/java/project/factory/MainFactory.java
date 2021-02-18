package project.factory;

import project.CONSTANTS;
import project.athena.Gen;
import project.dao.FRAKM;
import project.dao.PK_SK_FRAKM;
import project.dao.Randomness;
import project.dao.SK_R;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class MainFactory implements Factory {
    private final PK_SK_FRAKM pk_sk_m;
    private final SK_R sk_r;
    private final Gen gen;

    public MainFactory() {
        Randomness r = new Randomness(new Random(CONSTANTS.RANDOM_SEED).nextLong());
        this.gen = new Gen(r, CONSTANTS.KAPPA);
        this.pk_sk_m = gen.generate();
        this.sk_r = new SK_R(this.pk_sk_m.getSK(), r);
    }


    @Override
    public MessageDigest getHash() {

        MessageDigest sha3_256 = null;
        try {
            sha3_256 = MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return sha3_256;
    }

    @Override
    public ElGamal getElgamal() {
        return gen.getElGamal();
    }

    @Override
    public PK_SK_FRAKM getPK_SK_FRAKM() {
        return this.pk_sk_m;
    }

    @Override
    public SK_R getSK_R() {
        return this.sk_r;
    }

    @Override
    public ElGamalPK getPK() {
        return this.getPK_SK_FRAKM().getPK();
    }

    @Override
    public ElGamalSK getSK() {
        return this.sk_r.getElgamalSK();
    }

    @Override
    public FRAKM getFRAKM() {
        return this.getPK_SK_FRAKM().getFRAKM();
    }
}
