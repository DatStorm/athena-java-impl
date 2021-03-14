package athena;


import org.junit.jupiter.api.*;
import project.CONSTANTS;
import project.athena.AthenaImpl;
import project.athena.BulletinBoard;
import project.dao.athena.*;
import project.elgamal.ElGamalSK;
import project.factory.MainAthenaFactory;

import java.io.IOException;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

@Tag("TestsAthenaTally")
@DisplayName("Test Athena Tally")
public class TestAthenaTally {

    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;

    MainAthenaFactory msFactory;
    private CredentialTuple dv;
    private PK_Vector pkv;
    private ElGamalSK sk;

    private AthenaImpl athena;
    private BulletinBoard bb;


    @BeforeEach
    void setUp() {
        msFactory = new MainAthenaFactory();
        athena = new AthenaImpl(msFactory);
        ElectionSetup setup = athena.Setup(kappa, nc);

        sk = setup.sk;
        pkv = setup.pkv;
        RegisterStruct register = athena.Register(pkv);
        dv = register.d;
        bb = msFactory.getBulletinBoard();


    }

    @Disabled
    @Test
    void TestAthenaTally() {
        int nc = 10;

        int vote1_1 = 4;
        int cnt1_1 = 0;
        Ballot ballot_1 = athena.Vote(dv, pkv, vote1_1, cnt1_1, nc);
        

        int vote2_1 = 2;
        int cnt2_1 = 0;
        Ballot ballot_2 = athena.Vote(dv, pkv, vote2_1, cnt2_1, nc);
        
        TallyStruct tallyStruct = athena.Tally(new SK_Vector(sk),  nc);
        assertNotNull("Should not be null", tallyStruct.pf.mixBallotList);
        assertNotNull("Should not be null", tallyStruct.pf.pfd);
        assertNotNull("Should not be null", tallyStruct.pf.pfr);
        assertNotNull("Should not be null", tallyStruct.tallyOfVotes);


    }
}
