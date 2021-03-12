package athena;


import org.junit.jupiter.api.*;
import project.CONSTANTS;
import project.athena.AthenaImpl;
import project.athena.BulletinBoard;
import project.dao.athena.*;
import project.elgamal.ElGamalSK;
import project.factory.MainAthenaFactory;

import java.io.IOException;
import java.util.Arrays;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

@Tag("TestsAthenaTally")
@DisplayName("Test Athena Tally")
public class TestAthenaTally {

    MainAthenaFactory msFactory;
    private final int kappa = CONSTANTS.KAPPA;
    private CredentialTuple dv;
    private PK_Vector pkv;
    private ElGamalSK sk;

    private AthenaImpl athena;


    @BeforeEach
    void setUp() throws IOException {
        msFactory = new MainAthenaFactory();
        athena = new AthenaImpl(msFactory);
        SetupStruct setup = athena.Setup(kappa);

        sk = setup.sk;
        pkv = setup.pkv;
        RegisterStruct register = athena.Register(pkv, kappa);
        dv = register.d;

    }

    @Disabled
    @Test
    void TestAthenaTally() {
        int nc = 10;

        int vote1_1 = 4;
        int cnt1_1 = 0;
        Ballot ballot_1 = athena.Vote(dv, pkv, vote1_1, cnt1_1, nc, kappa);

        int vote2_1 = 2;
        int cnt2_1 = 0;
        Ballot ballot_2 = athena.Vote(dv, pkv, vote2_1, cnt2_1, nc, kappa);

        BulletinBoard bb = new BulletinBoard(Arrays.asList(ballot_1, ballot_2));
        TallyStruct tallyStruct = athena.Tally(new SK_Vector(sk), bb, nc, new ElectoralRoll(), kappa);
        assertNotNull("Should not be null", tallyStruct.pf.mixBallotList);
        assertNotNull("Should not be null", tallyStruct.pf.pfd);
        assertNotNull("Should not be null", tallyStruct.pf.pfr);
        assertNotNull("Should not be null", tallyStruct.votes_b);


    }
}
