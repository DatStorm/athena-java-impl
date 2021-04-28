package cs.au.athena.factory;

import cs.au.athena.CONSTANTS;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;

import java.util.Random;

public class MainFactory implements Factory {
    private final ElGamalSK sk;
    private final Random random;
    private final ElGamal elgamal;


    public MainFactory() {
        this.random = new Random(CONSTANTS.RANDOM_SEED);
        int nc = 10; //TODO: What value?;

        int bitlength = CONSTANTS.KAPPA * 8;
        this.elgamal = new ElGamal(CONSTANTS.ELGAMAL_CURRENT.GROUP, nc, random);
        this.sk = elgamal.generateSK();
    }

    @Override
    public ElGamal getElgamal() { return this.elgamal; }

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
