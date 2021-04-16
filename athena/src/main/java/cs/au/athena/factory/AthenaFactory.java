package cs.au.athena.factory;

import cs.au.athena.athena.BulletinBoard;
import cs.au.athena.athena.strategy.Strategy;

import java.util.Random;

public interface AthenaFactory extends SigmaFactory {

//    Sigma1 getSigma1();
//    Sigma2Pedersen getSigma2Pedersen();
//    Bulletproof getBulletProof();
//    Sigma3 getSigma3();
//    Sigma4 getSigma4();
//    Mixnet getMixnet(ElGamal elgamal, ElGamalPK pk);


    Random getRandom();

    BulletinBoard getBulletinBoard();

    Strategy getStrategy();
}
