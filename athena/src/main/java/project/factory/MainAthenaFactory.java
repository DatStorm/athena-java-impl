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
import project.sigma.sigma2.Sigma2;

import java.security.MessageDigest;
import java.util.Random;

public class MainAthenaFactory implements AthenaFactory {
    private final MessageDigest hash;
    private final Random random;


    public MainAthenaFactory() {
        this.random = new Random(CONSTANTS.RANDOM_SEED);
        this.hash = this.getHash();

    }

    @Override
    public Bulletproof getBulletProof() {
        return new Bulletproof(hash,random);
    }

    @Override
    public Sigma1 getSigma1() {
        return new Sigma1(hash);
    }

//    @Override
//    public Sigma2 getSigma2() {
//        return sigma2;
//    }

    @Override
    public Sigma3 getSigma3() {
        return new Sigma3(hash);
    }

    @Override
    public Sigma4 getSigma4() {
        return new Sigma4(hash);
    }

    @Override
    public Mixnet getMixnet(ElGamal elgamal, ElGamalPK pk) {
        return new Mixnet(this.hash, elgamal, pk, this.random);
    }

    @Override
    public Random getRandom() {
        if (random == null) {
            System.out.println("MainAthenaFactory.getRandom=> null");
        }
        return this.random;
    }

    @Override
    public MessageDigest getHash() {
        return UTIL.GET_HASH_FUNCTION();
    }

    @Override
    public BulletinBoard getBulletinBoard() {
        return BulletinBoard.getInstance();
    }


}
