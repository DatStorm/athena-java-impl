package project.generator;

import elgamal.ElGamal;
import elgamal.ElGamalSK;

public interface Generator {

    ElGamal getElGamal();

    ElGamalSK generate();
}
