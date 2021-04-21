package cs.au.athena.factory;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.distributed.AthenaDistributed;
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
    private final AthenaDistributed distributed;
    private final int tallierCount;
    private int kappa;


    public MainAthenaFactory(int tallierCount, int kappa) {
        this.tallierCount = tallierCount;
        this.kappa = kappa;
        this.random = new Random(CONSTANTS.RANDOM_SEED);
        this.distributed = new AthenaDistributed(this);




    }

    @Override
    public Sigma1 getSigma1() {
        return new Sigma1();
    }

    @Override
    public Bulletproof getBulletProof() {
        return new Bulletproof(this.random);
    }

    @Override
    public Sigma2Pedersen getSigma2Pedersen() {
        return new Sigma2Pedersen(this.random);
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
    public Mixnet getMixnet() {
        return new Mixnet(this.random);
    }

    @Override
    public Random getRandom() { return this.random; }

    @Override
    public BulletinBoardV2_0 getBulletinBoard() {
        return BulletinBoardV2_0.getInstance(this.tallierCount, this.kappa);
    }

    @Override
    public  AthenaDistributed getDistributedAthena() {
        return this.distributed;
    }


}
