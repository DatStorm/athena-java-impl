package cs.au.athena.athena;


import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import org.junit.jupiter.api.*;
import cs.au.athena.dao.athena.*;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.factory.MainAthenaFactory;

import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Tag("TestsAthenaVerify")
@DisplayName("Test Athena Verify")
public class TestAthenaVerify {
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;

    MainAthenaFactory msFactory;

    private ElGamalSK sk;
    private BulletinBoardV2_0 bb;

    private AthenaImpl athena;


    @BeforeEach
    void setUp() {
        msFactory = new MainAthenaFactory(CONSTANTS.SINGLE_TALLIER.TALLIER_COUNT,kappa);
        athena = new AthenaImpl(msFactory);
        sk = athena.Setup(CONSTANTS.SINGLE_TALLIER.TALLIER_INDEX,nc, kappa);

        bb = msFactory.getBulletinBoard();


    }

    /*********************************************
     * -------------------------------------------
     * -DO NOT RUN WITH LOW VALUES ELGAMAL VALUES-
     * -------------------------------------------
     ********************************************/
    @Disabled
    @RepeatedTest(100)
    void TestAthenaVerify() {

        RegisterStruct register1 = athena.Register(kappa);
        CredentialTuple dv1  = register1.d;
        int vote1_1 = 4;
        int cnt1_1 = 0;
        System.out.println("--> Voter 1: ");
        Ballot ballot_1 = athena.Vote(dv1, vote1_1, cnt1_1, nc,kappa);

        // Voter is now responsible for publishing.
        bb.publishBallot(ballot_1);
        System.out.println("--> Voter 1 done ");

        int vote2_1 = 2;
        int cnt2_1 = 0;
        RegisterStruct register2 = athena.Register(kappa);
        CredentialTuple dv2  = register2.d;
        System.out.println("--> Voter 2: ");


        Ballot ballot_2 = athena.Vote(dv2, vote2_1, cnt2_1, nc,kappa);
        System.out.println("--> Voter 2 done ");
        // Voter is now responsible for publishing.
        bb.publishBallot(ballot_2);


        System.out.println("--> Tally: ");
        Map<Integer, Integer> tally = athena.Tally(1, sk, nc, kappa);
        System.out.println("--> Tally done ");

        System.out.println("--> Verify: ");
        boolean verify = athena.Verify(kappa);
        System.out.println("--> Verify done ");
        assertTrue("should return 1", verify);
        
    }
}
