package athena;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.AthenaImpl;
import project.dao.athena.*;
import project.factory.MainAthenaFactory;

import java.io.IOException;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

@Tag("TestsAthenaVote")
@DisplayName("Test Athena Vote")
public class TestAthenaVote {

    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
    private final int kappa = CONSTANTS.KAPPA;
    
    MainAthenaFactory msFactory;
    private CredentialTuple dv;
    private PK_Vector pkv;

    private AthenaImpl athena;


    @BeforeEach
    void setUp() {
        msFactory = new MainAthenaFactory();
        athena = new AthenaImpl(msFactory);
        ElectionSetup setup = athena.Setup(kappa, nc);

        pkv = setup.pkv;
        RegisterStruct register = athena.Register(pkv);
        dv = register.d;

    }

    @Test
    void TestAthenaVote() {

        int vote = 4;
        int cnt = 0;
        int nc = 10;
        Ballot ballot = athena.Vote(dv, pkv, vote, cnt, nc);
        assertNotNull("Should not be null", ballot.getPublicCredential());
        assertNotNull("Should not be null", ballot.getEncryptedNegatedPrivateCredential());
        assertNotNull("Should not be null", ballot.getEncryptedVote());
        assertNotNull("Should not be null", ballot.getProofNegatedPrivateCredential());
        assertNotNull("Should not be null", ballot.getProofVote());
        assertNotEquals("Should not be 0",0, ballot.getCounter());
    }
}
