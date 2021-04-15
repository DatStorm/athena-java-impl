package cs.au.athena.generator;

import cs.au.athena.elgamal.Elgamal;
import cs.au.athena.elgamal.ElGamalSK;

public interface Generator {

    Elgamal getElGamal();

    ElGamalSK generate();
}
