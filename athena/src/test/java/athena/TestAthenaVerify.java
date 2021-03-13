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
import java.util.Arrays;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Tag("TestsAthenaVerify")
@DisplayName("Test Athena Verify")
public class TestAthenaVerify {

    MainAthenaFactory msFactory;
    private final int kappa = CONSTANTS.KAPPA;
    private CredentialTuple dv;
    private PK_Vector pkv;
    private ElGamalSK sk;
    private BulletinBoard bb;

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
        bb = msFactory.getBulletinBoard();


    }

    @Test
    void TestAthenaVerify() {
        int nc = 10;

        int vote1_1 = 4;
        int cnt1_1 = 0;
        System.out.println("--> Vote 1: ");
        Ballot ballot_1 = athena.Vote(dv, pkv, vote1_1, cnt1_1, nc, kappa);
        System.out.println("--> Vote 1 done ");

        int vote2_1 = 2;
        int cnt2_1 = 0;
        System.out.println("--> Vote 2: ");
        Ballot ballot_2 = athena.Vote(dv, pkv, vote2_1, cnt2_1, nc, kappa);
        System.out.println("--> Vote 2 done ");

        bb.addAllBallots(Arrays.asList(ballot_1, ballot_2));
        System.out.println("--> Tally: ");
        TallyStruct tallyStruct = athena.Tally(new SK_Vector(sk), bb, nc, kappa);
        System.out.println("--> Tally done ");

        Map<BigInteger, Integer> b = tallyStruct.votes_b;
        PFStruct pf = tallyStruct.pf;

        System.out.println("--> Verify: ");
        boolean verify = athena.Verify(pkv, bb, nc, b, pf, kappa);
        System.out.println("--> Verify done ");
        assertTrue("should return 1", verify);


    }
}
