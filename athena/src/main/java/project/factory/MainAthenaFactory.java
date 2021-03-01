package project.factory;

import project.CONSTANTS;
import project.UTIL;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.sigma2.Sigma2;

import java.security.MessageDigest;
import java.util.Random;

public class MainAthenaFactory implements AthenaFactory {
    private final Sigma1 sigma1;
    private final Sigma2 sigma2;
    private final Sigma3 sigma3;
    private final Sigma4 sigma4;
    private final Mixnet mixnet;
    private final MessageDigest hash;
    private final Random random;


    public MainAthenaFactory() {

        this.random = new Random(CONSTANTS.RANDOM_SEED);
        this.hash = this.getHash();
        sigma1 = new Sigma1(hash);
        sigma2 = new Sigma2(hash, this.random);
        sigma3 = new Sigma3(hash);
        sigma4 = new Sigma4(hash);
        mixnet = null;
    }


    @Override
    public Sigma1 getSigma1() {
        return sigma1;
    }

    @Override
    public Sigma2 getSigma2() {
        return sigma2;
    }

    @Override
    public Sigma3 getSigma3() {
        return sigma3;
    }

    @Override
    public Sigma4 getSigma4() {
        return sigma4;
    }

    @Override
    public Mixnet getMixnet() {
        if (mixnet == null) {
            System.out.println("MainAthenaFactory.getMixnet=> ERROR: mixnet is null needs to be set....");
        }
        return mixnet;
    }

    @Override
    public Random getRandom() {
        return this.random;
    }

    @Override
    public MessageDigest getHash() {
        return UTIL.GET_HASH_FUNCTION();
    }


}
