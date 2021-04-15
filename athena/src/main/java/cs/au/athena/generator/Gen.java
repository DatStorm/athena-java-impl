package cs.au.athena.generator;

import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.elgamal.ElGamalSK;

import java.util.Random;

public class Gen implements Generator {
    private final Elgamal elGamal;

    public Gen(Random random, int msgSpaceLength, int bitlength) {
        if(random == null){
            throw new RuntimeException("Gen() => Coins r is null");
        }
        if(bitlength == 0){
            throw new RuntimeException("Gen() => kappa is 0");
        }

        this.elGamal = new Elgamal(bitlength, msgSpaceLength, random);
    }

    @Override
    public Elgamal getElGamal() {
        return elGamal;
    }

    @Override
    public ElGamalSK generate() {
        return elGamal.generateSK();
    }
}
