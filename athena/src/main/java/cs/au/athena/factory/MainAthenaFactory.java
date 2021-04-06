package cs.au.athena.factory;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.BulletinBoard;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.mixnet.Mixnet;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma3;
import cs.au.athena.sigma.Sigma4;
import cs.au.athena.sigma.bulletproof.Bulletproof;

import java.util.Random;

public class MainAthenaFactory implements AthenaFactory {
    private final Random random;


    public MainAthenaFactory() {
        this.random = new Random(CONSTANTS.RANDOM_SEED);

    }

    @Override
    public Bulletproof getBulletProof() {
        return new Bulletproof(random);
    }

    @Override
    public Sigma1 getSigma1() {
        return new Sigma1();
    }
    

    @Override
    public Sigma3 getSigma3() {
        return new Sigma3();
    }

    @Override
    public Sigma4 getSigma4() {
        return new Sigma4();
    }

    @Override
    public Mixnet getMixnet(ElGamal elgamal, ElGamalPK pk) {
        return new Mixnet(elgamal, pk, this.random);
    }

    @Override
    public Random getRandom() { return this.random; }

   
    @Override
    public BulletinBoard getBulletinBoard() {
        return BulletinBoard.getInstance();
    }


}