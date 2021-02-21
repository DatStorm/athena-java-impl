package project.dao.mixnet;

import project.elgamal.CipherText;

import java.util.List;
import java.util.Map;

public class MixnetProof {
    private final List<CipherText> listOfBj_prime;
    private final Map<Integer, List<CipherText>> mapOfBj;

    public MixnetProof(List<CipherText> listOfBj_prime, Map<Integer, List<CipherText>> mapOfBj) {
        this.listOfBj_prime = listOfBj_prime;
        this.mapOfBj = mapOfBj;
    }

    public Map<Integer, List<CipherText>> getMapOfBj() {
        return mapOfBj;
    }

//     public Map<Integer, List<>>

}
