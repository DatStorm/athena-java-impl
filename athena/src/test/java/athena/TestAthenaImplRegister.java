package athena;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.AthenaImpl;
import project.dao.athena.PK_Vector;
import project.dao.athena.RegisterStruct;
import project.dao.athena.SetupStruct;
import project.factory.MainAthenaFactory;

import java.io.IOException;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

@Tag("TestsAthenaRegister")
@DisplayName("Test Athena Register")
public class TestAthenaImplRegister {

    MainAthenaFactory msFactory;
    private final int kappa = CONSTANTS.KAPPA;


    @BeforeEach
    void setUp() {
        msFactory = new MainAthenaFactory();
    }

    @Test
    void TestAthenaRegister() throws IOException {

        AthenaImpl athena = new AthenaImpl(msFactory);
        SetupStruct setup = athena.Setup(kappa);

        RegisterStruct register = athena.Register(setup.pkv, kappa);

        assertNotNull("Should not be null", register.pd);
        assertNotNull("Should not be null", register.d);
    }
}
