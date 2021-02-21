package project.dao.mixnet;

import java.math.BigInteger;
import java.util.List;

public class Step1Statement {
    private final List<BigInteger> listOfRandR;
    private final List<BigInteger> listOfRandS;
    private final List<MixBallot> listOfBi_prime;

    public Step1Statement(List<BigInteger> listOfRandR, List<BigInteger> listOfRandS, List<MixBallot> listOfBi_prime) {
        this.listOfRandR = listOfRandR;
        this.listOfRandS = listOfRandS;
        this.listOfBi_prime = listOfBi_prime;
    }

    public List<BigInteger> getListOfRandR() {
        return listOfRandR;
    }

    public List<BigInteger> getListOfRandS() {
        return listOfRandS;
    }

    public List<MixBallot> getListOfBi_prime() {
        return listOfBi_prime;
    }
    
}
