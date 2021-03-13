package project.dao.athena;

import project.elgamal.CipherText;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ElectoralRoll {
    private List<CipherText> listOfPublicCredentials;

    public ElectoralRoll() {
        this.listOfPublicCredentials = new ArrayList<>();
    }


    public void add(CipherText publicCredential) {
        this.listOfPublicCredentials.add(publicCredential);
    }

    // Check that the publicCredential is in the electoral roll
    public boolean contains(CipherText publicCredential) {
        return listOfPublicCredentials.contains(publicCredential);
    }
}