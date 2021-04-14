package cs.au.athena.factory;

import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.mixnet.Mixnet;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma2Pedersen;
import cs.au.athena.sigma.Sigma3;
import cs.au.athena.sigma.Sigma4;
import cs.au.athena.sigma.bulletproof.Bulletproof;

public interface SigmaFactory {
    Sigma1 getSigma1();
    Sigma2Pedersen getSigma2Pedersen();
    Bulletproof getBulletProof();
    Sigma3 getSigma3();
    Sigma4 getSigma4();
    Mixnet getMixnet(ElGamal elgamal, ElGamalPK pk);
}
