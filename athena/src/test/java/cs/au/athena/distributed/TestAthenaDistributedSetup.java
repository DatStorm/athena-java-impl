package cs.au.athena.distributed;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.AthenaImpl;
import cs.au.athena.athena.distributed.AthenaImplDistributed;
import cs.au.athena.dao.athena.ElectionSetup;
import cs.au.athena.factory.MainAthenaFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertNotNull;


@Tag("TestAthenaDistributedSetup")
@DisplayName("Test Athena Distributed Setup")
public class TestAthenaDistributedSetup {
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;

    MainAthenaFactory maFactory;

    @BeforeEach
    void setUp() {
        maFactory = new MainAthenaFactory();
    }


    @Test
    void TestAthenaSetup() {
        AthenaImplDistributed athenaDist = new AthenaImplDistributed(maFactory);

        ElectionSetup setup = athenaDist.Setup(nc, kappa);

        MatcherAssert.assertThat("Should not be null", setup.sk, notNullValue());
    }
}
