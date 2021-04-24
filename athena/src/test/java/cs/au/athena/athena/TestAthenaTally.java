package cs.au.athena.athena;


import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import org.junit.jupiter.api.*;
import cs.au.athena.dao.athena.*;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.MainAthenaFactory;

import java.util.Map;

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

    private Athena athena;
    private BulletinBoard bb;


    @BeforeEach
    void setUp() {
        msFactory = new MainAthenaFactory(CONSTANTS.SINGLE_TALLIER.TALLIER_COUNT,kappa);
        athena = new AthenaImpl(msFactory);
        ElGamalSK sk = athena.Setup(CONSTANTS.SINGLE_TALLIER.TALLIER_INDEX,nc, this.kappa);
//        bb = msFactory.getBulletinBoard();
        bb = BulletinBoard.getInstance(); // TODO: RePLACE WITH ABOVE WHEN BB IS DONE!

        pkv = bb.retrievePK_vector();
        RegisterStruct register = athena.Register(this.kappa);
        dv = register.d;


    }

    @Disabled
    @Test
    void TestAthenaTally() {
        int nc = 10;

        int vote1_1 = 4;
        int cnt1_1 = 0;
        Ballot ballot_1 = athena.Vote(dv, vote1_1, cnt1_1, nc, this.kappa);


        int vote2_1 = 2;
        int cnt2_1 = 0;
        Ballot ballot_2 = athena.Vote(dv, vote2_1, cnt2_1, nc, kappa);

        Map<Integer, Integer> tally = athena.Tally(1, sk, nc, this.kappa);
        assertNotNull("Should not be null", tally);


    }
}
