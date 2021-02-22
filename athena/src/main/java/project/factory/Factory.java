package project.factory;

import project.dao.MessageSpace;
import project.dao.PK_SK_FRAKM;
import project.dao.SK_R;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.security.MessageDigest;
import java.util.Random;

public interface Factory {
    MessageDigest getHash();
    ElGamal getElgamal();
    ElGamalPK getPK();
    ElGamalSK getSK();
    Random getRandom();
}
