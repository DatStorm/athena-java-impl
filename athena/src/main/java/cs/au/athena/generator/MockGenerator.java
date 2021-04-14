package cs.au.athena.generator;

import cs.au.athena.CONSTANTS;
import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;

import java.math.BigInteger;
import java.util.Random;

public class MockGenerator implements Generator {
    private final ElGamal elGamal; 
    
    public MockGenerator(Random random, int nc, int bitlength) {

        if(random == null){
            throw new RuntimeException("Gen() => Coins r is null");
        }
        if(bitlength == 0){
            throw new RuntimeException("Gen() => kappa is 0");
        }

        BigInteger p = CONSTANTS.ELGAMAL_CURRENT.ELGAMAL_P;
        BigInteger q = CONSTANTS.ELGAMAL_CURRENT.ELGAMAL_Q;
        BigInteger g = CONSTANTS.ELGAMAL_CURRENT.ELGAMAL_G;

        Group mockGroup = new Group(p, q, g);

        this.elGamal = new ElGamal(mockGroup, nc,random);
    }

    @Override
    public ElGamal getElGamal() {
        return this.elGamal;
    }

    @Override
    public ElGamalSK generate() {
        return elGamal.generateSK();
    }
}
