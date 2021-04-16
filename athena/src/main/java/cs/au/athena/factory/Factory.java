package cs.au.athena.factory;

import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.elgamal.ElGamalPK;
import cs.au.athena.elgamal.ElGamalSK;

import java.util.Random;

public interface Factory {
    Elgamal getElgamal();
    ElGamalPK getPK();
    ElGamalSK getSK();
    Random getRandom();
}
