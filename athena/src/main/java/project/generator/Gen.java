package project.generator;

import elgamal.ElGamal;
import elgamal.ElGamalSK;

import java.util.Random;

public class Gen implements Generator {
    private final ElGamal elGamal;

    public Gen(Random random, int msgSpaceLength, int bitlength) {
        if(random == null){
            throw new RuntimeException("Gen() => Coins r is null");
        }
        if(bitlength == 0){
            throw new RuntimeException("Gen() => kappa is 0");
        }

        this.elGamal = new ElGamal(bitlength, msgSpaceLength, random);
    }

    @Override
    public ElGamal getElGamal() {
        return elGamal;
    }

    @Override
    public ElGamalSK generate() {
        return elGamal.generateSK();
    }
}
