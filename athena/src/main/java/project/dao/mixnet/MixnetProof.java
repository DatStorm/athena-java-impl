package project.dao.mixnet;

import project.elgamal.CipherText;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

public class MixnetProof {
    private final List<MixBallot> listOfBj_prime;
    private final Map<Integer, List<MixBallot>> mapOfBj;
    private final Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessR;
    private final Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessS;
    private final Map<Integer, List<Integer>> mapOfPermDataBj;

    public MixnetProof(List<MixBallot> listOfBj_prime,
                       Map<Integer, List<MixBallot>> mapOfBj,
                       Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessR,
                       Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessS,
                       Map<Integer, List<Integer>> mapOfPermDataBj) {

        this.listOfBj_prime = listOfBj_prime;
        this.mapOfBj = mapOfBj;
        this.mapOfReencDataBjRandomnessR = mapOfReencDataBjRandomnessR;
        this.mapOfReencDataBjRandomnessS = mapOfReencDataBjRandomnessS;
        this.mapOfPermDataBj = mapOfPermDataBj;
    }

    public Map<Integer, List<MixBallot>> getMapOfBj() {
        return mapOfBj;
    }

    public List<MixBallot> getListOfBj_prime() {
        return listOfBj_prime;
    }

    public Map<Integer, List<BigInteger>> getMapOfReencDataBjRandomnessR() {
        return mapOfReencDataBjRandomnessR;
    }

    public Map<Integer, List<BigInteger>> getMapOfReencDataBjRandomnessS() {
        return mapOfReencDataBjRandomnessS;
    }

    public Map<Integer, List<Integer>> getMapOfPermDataBj() {
        return mapOfPermDataBj;
    }
    
}
