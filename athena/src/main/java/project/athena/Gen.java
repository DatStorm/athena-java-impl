package project.athena;

import project.CONSTANTS;
import project.dao.FRAKM;
import project.dao.Randomness;
import project.dao.PK_SK_FRAKM;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.math.BigInteger;
import java.util.Random;

public class Gen {
    private final ElGamal elGamal;

    public Gen(Randomness r, int kappa) {
        if(r == null){
            throw new RuntimeException("Gen() => Coins r is null");
        }
        if(kappa == 0){
            throw new RuntimeException("Gen() => kappa is 0");
        }

        this.elGamal = new ElGamal(kappa, new Random(r.getValue()));
    }

    public ElGamal getElGamal() {
        return elGamal;
    }

    public PK_SK_FRAKM generate() {
        ElGamalSK sk = elGamal.generateSK();
        ElGamalPK pk = elGamal.generatePk(sk);

        BigInteger start = BigInteger.ONE;
        BigInteger end = elGamal.getP().subtract(BigInteger.ONE); //TODO: How is this group defined? Is it continuous
        FRAKM frakm = new FRAKM(start, end);


        return new PK_SK_FRAKM(pk,sk,frakm);
    }
}
