package project.athena;

import project.dao.Randomness;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalSK;

import java.util.Random;

public class Gen {
    private final ElGamal elGamal;

    public Gen(Random random, int kappa) {
        if(random == null){
            throw new RuntimeException("Gen() => Coins r is null");
        }
        if(kappa == 0){
            throw new RuntimeException("Gen() => kappa is 0");
        }

        this.elGamal = new ElGamal(kappa, random);
    }

    public ElGamal getElGamal() {
        return elGamal;
    }

    public ElGamalSK generate() {
        return elGamal.generateSK();
    }
}
