package project.factory;

import project.CONSTANTS;
import project.athena.Gen;
import project.dao.Randomness;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class MainFactory implements Factory {
    private final ElGamalSK sk;
    private final Gen gen;
    private final Random random;


    public MainFactory() {
        this.random = new Random(CONSTANTS.RANDOM_SEED);
        this.gen = new Gen(new Randomness(this.random.nextLong()), CONSTANTS.KAPPA);
        this.sk = gen.generate();
    }


    @Override
    public MessageDigest getHash() {

        MessageDigest sha3_256 = null;
        try {
            sha3_256 = MessageDigest.getInstance(CONSTANTS.ALGORITHM_SHA3_256);
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
    public ElGamalPK getPK() {
        return this.sk.pk;
    }

    @Override
    public ElGamalSK getSK() {
        return this.sk;
    }


    @Override
    public Random getRandom() { return this.random; }


}
