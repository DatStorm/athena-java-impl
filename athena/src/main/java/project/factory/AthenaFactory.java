package project.factory;

import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.sigma2.Sigma2;

import java.security.MessageDigest;
import java.util.Random;

public interface AthenaFactory {

    Sigma1 getSigma1();
    Sigma2 getSigma2();
    Sigma3 getSigma3();
    Sigma4 getSigma4();
    Mixnet getMixnet();
    Random getRandom();

    MessageDigest getHash();
}
