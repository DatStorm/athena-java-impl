package project.dao.athena;

import project.elgamal.Ciphertext;

import java.util.ArrayList;
import java.util.List;

public class ElectoralRoll {
    private List<Ciphertext> listOfPublicCredentials;

    public ElectoralRoll() {
        this.listOfPublicCredentials = new ArrayList<>();
    }


    public void add(Ciphertext publicCredential) {
        this.listOfPublicCredentials.add(publicCredential);
    }

    // Check that the publicCredential is in the electoral roll
    public boolean contains(Ciphertext publicCredential) {
        return listOfPublicCredentials.contains(publicCredential);
    }

    @Override
    public String toString() {
        StringBuilder res = new StringBuilder();

        for (Ciphertext pd : listOfPublicCredentials) {
            res.append(pd.toShortString()).append(", ");
        }

        return "[" + res.toString() + ']';
    }
}