package project.factory;

import project.CONSTANTS;
import project.UTIL;
import project.athena.BulletinBoard;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;

import java.security.MessageDigest;
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
