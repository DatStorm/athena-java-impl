package athena;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.athena.AthenaImpl;
import project.dao.athena.ElectionSetup;
import project.factory.MainAthenaFactory;


import java.io.IOException;

import static org.junit.Assert.*;


@Tag("TestsAthenaSetup")
@DisplayName("Test Athena Setup")
public class TestAthenaSetup {
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;

    MainAthenaFactory maFactory;



    @BeforeEach
    void setUp() {
        maFactory = new MainAthenaFactory();
    }


    @Test
    void TestAthenaSetup() {

        AthenaImpl athena = new AthenaImpl(maFactory);
        ElectionSetup setup = athena.Setup(kappa, nc);

        assertNotEquals("Should not be 0", 0, setup.mb);
        assertNotEquals("Should not be 0", 0, setup.mc);
        assertNotNull("Should not be null", setup.pkv);
        assertNotNull("Should not be null", setup.sk);
    }
}
