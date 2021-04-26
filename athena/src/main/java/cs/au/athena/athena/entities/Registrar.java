package cs.au.athena.athena.entities;

import cs.au.athena.athena.Athena;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.dao.athena.CredentialTuple;
import cs.au.athena.dao.athena.PK_Vector;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * The role of the Registrar(trusted party) in Athena is the following:
 * - Invoke Register() to contruct credentials and add the public credential to Electoral Roll on BulletinBoard.
 * -  Issue credentials privately to each voter.
 **/
public class Registrar {
    private List<CredentialTuple> credentialList;
    private final Athena athena;
    private int kappa;

    public Registrar(Athena athena, BulletinBoardV2_0 bulletinBoard, int kappa) {
        this.athena = athena;
        this.kappa = kappa;
    }

    public Registrar(Athena athena, int kappa) {
        this.athena = athena;
        this.kappa = kappa;
    }

    // Fetch the pk and proof ProveKey
    public void init() {
    }

    // Generate list of (public credential, private credential) for certain number of voters.
    public boolean generateCredentials(int numVoters) {
        credentialList = new ArrayList<>();

        // Run Register(numVoters)
        credentialList = IntStream.range(0, numVoters).mapToObj(i -> athena.Register(kappa).d).collect(Collectors.toList());
        boolean success = credentialList.size() == numVoters;
        assert success : "credentialList.size() != numVoters";
        return success;
    }


    // Use for local communication
    public CredentialTuple sendCredentials(int index) {
        if (credentialList.isEmpty()) {
            System.err.println("Registrar.sendCredentials => the list of credentials produced is empty!");
            return null;
        }

        if (!(index >= 0 && index < credentialList.size())) {
            System.err.println("Registrar.sendCredentials => the list of credentials produced is < 0 or >size!");
            return null;
        }

        CredentialTuple credentials = credentialList.get(index);
        return credentials;
    }

}
