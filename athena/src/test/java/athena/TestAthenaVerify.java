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

    @Test
    void TestAthenaVerify() {
        int nc = 10;

        int vote1_1 = 4;
        int cnt1_1 = 0;
        Ballot ballot_1 = athena.Vote(dv, pkv, vote1_1, cnt1_1, nc, kappa);

        int vote2_1 = 2;
        int cnt2_1 = 0;
        Ballot ballot_2 = athena.Vote(dv, pkv, vote2_1, cnt2_1, nc, kappa);

        BulletinBoard bb = new BulletinBoard(Arrays.asList(ballot_1, ballot_2));
        ElectoralRoll L = new ElectoralRoll();
        TallyStruct tallyStruct = athena.Tally(new SK_Vector(sk), bb, nc, L, kappa);

        Map<BigInteger, Integer> b = tallyStruct.votes_b;
        PFStruct pf = tallyStruct.pf;

        boolean verify = athena.Verify(pkv, bb, nc, L, b, pf, kappa);
        assertTrue("should return 1", verify);


    }
}
