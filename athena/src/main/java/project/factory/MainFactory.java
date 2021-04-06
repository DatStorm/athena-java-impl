package project.factory;

import project.CONSTANTS;
import project.generator.Gen;
import elgamal.ElGamal;
import elgamal.ElGamalPK;
import elgamal.ElGamalSK;

import java.util.Random;

public class MainFactory implements Factory {
    private final ElGamalSK sk;
    private final Gen gen;
    private final Random random;


    public MainFactory() {
        this.random = new Random(CONSTANTS.RANDOM_SEED);
        int bitlength = CONSTANTS.KAPPA * 8;
        this.gen = new Gen(this.random,CONSTANTS.MSG_SPACE_LENGTH, bitlength);
        this.sk = gen.generate();
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
