package project.factory;

import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.security.MessageDigest;
import java.util.Random;

public interface Factory {
    ElGamal getElgamal();
    ElGamalPK getPK();
    ElGamalSK getSK();
    Random getRandom();
}
