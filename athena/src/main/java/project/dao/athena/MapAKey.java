package project.dao.athena;

import project.elgamal.CipherText;

import java.math.BigInteger;

public class MapAKey {
    public final CipherText bi1;
    public final BigInteger n;

    public MapAKey(CipherText bi1, BigInteger N) {

        this.bi1 = bi1;
        n = N;
    }
}
