package cs.au.athena.athena;


import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.elgamal.ElGamalSK;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.athena.RegisterStruct;
import cs.au.athena.factory.MainAthenaFactory;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

@Tag("TestsAthenaRegister")
@DisplayName("Test Athena Register")
public class TestAthenaRegister {

    MainAthenaFactory msFactory;
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;


    @BeforeEach
    void setUp() {
        msFactory = new MainAthenaFactory(CONSTANTS.SINGLE_TALLIER.TALLIER_COUNT,kappa);
    }

    @Test
    void TestAthenaImplRegister() {
        AthenaImpl athena = new AthenaImpl(msFactory);
        athena.Setup(CONSTANTS.SINGLE_TALLIER.TALLIER_INDEX,nc, kappa);

        RegisterStruct register = athena.Register(kappa);

        MatcherAssert.assertThat("Should not be null", register.pd, notNullValue());
        MatcherAssert.assertThat("Should not be null", register.d, notNullValue());
    }
}
