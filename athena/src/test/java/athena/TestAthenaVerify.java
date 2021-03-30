package athena;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.AthenaImpl;
import project.athena.BulletinBoard;
import project.dao.athena.*;
import project.elgamal.ElGamalSK;
import project.factory.MainAthenaFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Tag("TestsAthenaVerify")
@DisplayName("Test Athena Verify")
public class TestAthenaVerify {
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;

    MainAthenaFactory msFactory;

    private PK_Vector pkv;
    private ElGamalSK sk;
    private BulletinBoard bb;

    private AthenaImpl athena;


    @BeforeEach
    void setUp() {
        msFactory = new MainAthenaFactory();
        athena = new AthenaImpl(msFactory);
        ElectionSetup setup = athena.Setup(nc, kappa);

        sk = setup.sk;
        pkv = setup.pkv;

        bb = msFactory.getBulletinBoard();


    }

    @Test
    void TestAthenaVerify() {

        RegisterStruct register1 = athena.Register(pkv,kappa);
        CredentialTuple dv1  = register1.d;
        int vote1_1 = 4;
        int cnt1_1 = 0;
        System.out.println("--> Voter 1: ");
        Ballot ballot_1 = athena.Vote(dv1, pkv, vote1_1, cnt1_1, nc,kappa);

        // Voter is now responsible for publishing.
        bb.publishBallot(ballot_1);
        System.out.println("--> Voter 1 done ");

        int vote2_1 = 2;
        int cnt2_1 = 0;
        RegisterStruct register2 = athena.Register(pkv,kappa);
        CredentialTuple dv2  = register2.d;
        System.out.println("--> Voter 2: ");


        Ballot ballot_2 = athena.Vote(dv2, pkv, vote2_1, cnt2_1, nc,kappa);
        System.out.println("--> Voter 2 done ");
        // Voter is now responsible for publishing.
        bb.publishBallot(ballot_2);


        System.out.println("--> Tally: ");
        TallyStruct tallyStruct = athena.Tally(new SK_Vector(sk), nc, kappa);
        System.out.println("--> Tally done ");

        Map<Integer, Integer> b = tallyStruct.tallyOfVotes;
        PFStruct pf = tallyStruct.pf;

        System.out.println("--> Verify: ");
        boolean verify = athena.Verify(pkv, nc, b, pf, kappa);
        System.out.println("--> Verify done ");
        assertTrue("should return 1", verify);
        
    }
}
