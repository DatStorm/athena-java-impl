package project.factory;

import project.dao.FRAKM;
import project.dao.PK_SK_FRAKM;
import project.dao.Randomness;
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
    PK_SK_FRAKM getPK_SK_FRAKM();
    SK_R getSK_R();
    FRAKM getFRAKM();
    Random getRandom();
}
