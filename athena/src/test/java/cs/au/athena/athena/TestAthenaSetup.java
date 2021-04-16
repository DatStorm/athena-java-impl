package cs.au.athena.athena;

import cs.au.athena.factory.AthenaFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.athena.ElectionSetup;
import cs.au.athena.factory.MainAthenaFactory;


import static org.junit.Assert.*;


@Tag("TestsAthenaSetup")
@DisplayName("Test Athena Setup")
public class TestAthenaSetup {
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;

    MainAthenaFactory maFactory;



    @BeforeEach
    void setUp() {
        maFactory = new MainAthenaFactory(AthenaFactory.STRATEGY.SINGLE);
    }


    @Test
    void TestAthenaSetup() {
        AthenaImpl athena = new AthenaImpl(maFactory);
        ElectionSetup setup = athena.Setup(nc,kappa);
        assertNotNull("Should not be null", setup.sk);
    }
}
