package project.athena;

import project.CONSTANTS;
import project.dao.FRAKM;
import project.dao.Randomness;
import project.dao.PK_SK_FRAKM;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;

import java.math.BigInteger;

public class Gen {
    private final ElGamal elGamal;

    public Gen(Randomness r, int kappa) {
        if(r == null){
            throw new RuntimeException("Gen() => Coins r is null");
        }
        if(kappa == 0){
            throw new RuntimeException("Gen() => kappa is null");
        }

        this.elGamal = new ElGamal(CONSTANTS.ELGAMAL_BIT_LENGTH);

        System.err.println("COINS AND KAPPA NOT USED!!");
    }

    public PK_SK_FRAKM generate() {
        ElGamalSK sk = elGamal.generateSk();
        ElGamalPK pk = elGamal.generatePk(sk);

        BigInteger start = BigInteger.ONE;
        BigInteger end = elGamal.getP().subtract(BigInteger.ONE); //TODO: How is this group defined? Is it continuous
        FRAKM frakm = new FRAKM(start, end);


        return new PK_SK_FRAKM(pk,sk,frakm);
    }
}
