package project.factory;

import elgamal.ElGamal;
import elgamal.ElGamalPK;
import elgamal.ElGamalSK;

import java.util.Random;

public interface Factory {
    ElGamal getElgamal();
    ElGamalPK getPK();
    ElGamalSK getSK();
    Random getRandom();
}
