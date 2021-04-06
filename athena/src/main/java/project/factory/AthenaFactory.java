package project.factory;

import athena.BulletinBoard;
import elgamal.ElGamal;
import elgamal.ElGamalPK;
import mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;

import java.util.Random;

public interface AthenaFactory {

    Sigma1 getSigma1();
//    Sigma2 getSigma2();
    Bulletproof getBulletProof();
    Sigma3 getSigma3();
    
    Sigma4 getSigma4();
    Mixnet getMixnet(ElGamal elgamal, ElGamalPK pk);
    Random getRandom();

    BulletinBoard getBulletinBoard();
}
