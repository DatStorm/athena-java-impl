package cs.au.athena.generator;

import cs.au.athena.elgamal.ElGamal;
import cs.au.athena.elgamal.ElGamalSK;

public interface Generator {

    ElGamal getElGamal();

    ElGamalSK generate();
}
