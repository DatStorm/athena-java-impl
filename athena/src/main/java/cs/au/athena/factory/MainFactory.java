package cs.au.athena.factory;

import cs.au.athena.CONSTANTS;
import cs.au.athena.generator.Gen;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.generator.Generator;
import cs.au.athena.generator.MockGenerator;

import java.util.Random;

public class MainFactory implements Factory {
    private final ElGamalSK sk;
    private final Generator gen;
    private final Random random;


    public MainFactory() {
        this.random = new Random(CONSTANTS.RANDOM_SEED);
        int bitlength = CONSTANTS.KAPPA * 8;
//        this.gen = new Gen(this.random, CONSTANTS.MSG_SPACE_LENGTH, bitlength);
        int nc = ??;
        this.gen = new MockGenerator(random, nc, bitlength);
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
