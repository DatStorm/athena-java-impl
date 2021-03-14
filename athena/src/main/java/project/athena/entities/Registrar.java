package project.athena.entities;

import project.athena.Athena;
import project.athena.BulletinBoard;
import project.dao.athena.CredentialTuple;
import project.dao.athena.PK_Vector;
import project.dao.athena.RegisterStruct;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * The role of the Registrar(trusted party) in Athena is the following:
 * - Invoke Register() to contruct credentials and add the public credential to Electoral Roll on BulletinBoard.
 * -  Issue credentials privately to each voter.
 **/
public class Registrar implements Entity{
    private List<CredentialTuple> credentialList;
    private Athena athena;
    private BulletinBoard bulletinBoard;
    private PK_Vector pkVector;

    public Registrar(Athena athena, BulletinBoard bulletinBoard) {
        this.athena = athena;
        this.bulletinBoard = bulletinBoard;
    }

    // Fetch the pk and proof ProveKey
    public void init() {
        pkVector = bulletinBoard.retrievePK_vector();
    }

    // Generate list of (public credential, private credential) for certain number of voters.
    public boolean generateCredentials(int numVoters) {
        if (pkVector == null) {
            System.err.println("Registrar.generateCredentials => pkVector is null! Please run Registrar.init()");
            return false;
        }
        credentialList = new ArrayList<>();

        // Run Register(numVoters)
        credentialList = IntStream.range(0, numVoters).mapToObj(i -> athena.Register(pkVector).d).collect(Collectors.toList());
        boolean success = credentialList.size() == numVoters;
                
        return success;
    }


    // Use for local communication
    public CredentialTuple sendCredentials(int index) {
        if (credentialList.isEmpty()) {
            System.err.println("Registrar.sendCredentials => the list of credentials produced is empty!");
            return null;
        }
        
        CredentialTuple credentials = credentialList.get(index);
        return credentials;
    }

}
