package cs.au.athena.factory;

import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;

import java.util.Random;

public interface Factory {
    ElGamal getElgamal();
    ElGamalPK getPK();
    ElGamalSK getSK();
    Random getRandom();
}
