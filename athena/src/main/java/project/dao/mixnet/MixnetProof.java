package project.dao.mixnet;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

public class MixnetProof {
    private final List<MixBallot> listOfB_prime;
    private final Map<Integer, List<MixBallot>> mapOfBj;
    private final Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessR;
    private final Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessS;
    private final Map<Integer, List<Integer>> mapOfPermutationDataBj;

    public MixnetProof(List<MixBallot> listOfB_prime,
                       Map<Integer, List<MixBallot>> mapOfBj,
                       Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessR,
                       Map<Integer, List<BigInteger>> mapOfReencDataBjRandomnessS,
                       Map<Integer, List<Integer>> mapOfPermutationDataBj) {

        this.listOfB_prime = listOfB_prime;
        this.mapOfBj = mapOfBj;
        this.mapOfReencDataBjRandomnessR = mapOfReencDataBjRandomnessR;
        this.mapOfReencDataBjRandomnessS = mapOfReencDataBjRandomnessS;
        this.mapOfPermutationDataBj = mapOfPermutationDataBj;
    }

    public Map<Integer, List<MixBallot>> getMapOfBj() {
        return mapOfBj;
    }

    public List<MixBallot> getListOfB_prime() {
        return listOfB_prime;
    }

    public Map<Integer, List<BigInteger>> getMapOfReencDataBjRandomnessR() {
        return mapOfReencDataBjRandomnessR;
    }

    public Map<Integer, List<BigInteger>> getMapOfReencDataBjRandomnessS() {
        return mapOfReencDataBjRandomnessS;
    }


    public Map<Integer, List<Integer>> getMapOfPermutationDataBj() {
        return mapOfPermutationDataBj;
    }


    @Override
    public String toString() {
        return "MixnetProof{" +
                "listOfB_prime=" + listOfB_prime +
                ", mapOfBj=" + mapOfBj +
                ", mapOfReencDataBjRandomnessR=" + mapOfReencDataBjRandomnessR +
                ", mapOfReencDataBjRandomnessS=" + mapOfReencDataBjRandomnessS +
                ", mapOfPermutationDataBj=" + mapOfPermutationDataBj +
                '}';
    }
}
