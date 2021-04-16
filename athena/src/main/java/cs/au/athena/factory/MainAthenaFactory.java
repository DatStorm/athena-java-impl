package cs.au.athena.factory;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.BulletinBoard;
import cs.au.athena.athena.strategy.SingleTallierStrategy;
import cs.au.athena.athena.strategy.Strategy;
import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.mixnet.Mixnet;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma2Pedersen;
import cs.au.athena.sigma.Sigma3;
import cs.au.athena.sigma.Sigma4;
import cs.au.athena.sigma.bulletproof.Bulletproof;

import java.util.Random;


// Factory for constructing Sigma objects
public class MainAthenaFactory implements AthenaFactory {
    private final Random random;
    private final Strategy strategy;


    public MainAthenaFactory() {
        this.random = new Random(CONSTANTS.RANDOM_SEED);
        this.strategy = new SingleTallierStrategy(this);
    }


    @Override
    public Sigma1 getSigma1() { return new Sigma1(); }

    @Override
    public Bulletproof getBulletProof() { return new Bulletproof(this.random); }

    @Override
    public Sigma2Pedersen getSigma2Pedersen() { return new Sigma2Pedersen(this.random); }

    @Override
    public Sigma3 getSigma3() { return new Sigma3(); }

    @Override
    public Sigma4 getSigma4() {
        return new Sigma4();
    }

    @Override
    public Mixnet getMixnet(Elgamal elgamal, ElGamalPK pk) {
        return new Mixnet(elgamal, this.random);
    }

    @Override
    public Random getRandom() { return this.random; }

    @Override
    public BulletinBoard getBulletinBoard() {
        return BulletinBoard.getInstance();
    }

    @Override
    public Strategy getStrategy() { return this.strategy; }


}
