package cs.au.athena.athena;


import cs.au.athena.CONSTANTS;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.dao.athena.RegisterStruct;
import cs.au.athena.dao.athena.ElectionSetup;
import cs.au.athena.factory.MainAthenaFactory;

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
        msFactory = new MainAthenaFactory();
    }

    @Test
    void TestAthenaImplRegister() {
        AthenaImpl athena = new AthenaImpl(msFactory);
        ElectionSetup setup = athena.Setup(nc,kappa);

        PK_Vector pkv = msFactory.getBulletinBoard().retrievePK_vector();

        RegisterStruct register = athena.Register(pkv, kappa);

        assertNotNull("Should not be null", register.pd);
        assertNotNull("Should not be null", register.d);
    }
}