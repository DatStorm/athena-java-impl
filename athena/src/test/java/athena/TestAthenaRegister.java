package athena;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.AthenaImpl;
import project.dao.athena.RegisterStruct;
import project.dao.athena.ElectionSetup;
import project.factory.MainAthenaFactory;

import java.io.IOException;

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

        RegisterStruct register = athena.Register(setup.pkv, kappa);

        assertNotNull("Should not be null", register.pd);
        assertNotNull("Should not be null", register.d);
    }
}
