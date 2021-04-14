package cs.au.athena.distributed;

import cs.au.athena.CONSTANTS;
import cs.au.athena.dao.athena.ElectionSetup;
import cs.au.athena.factory.MainAthenaFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertNotNull;


@Tag("TestAthenaDistributedStrategy")
@DisplayName("Test Athena Distributed Strategy")
public class TestAthenaDistributedStrategy {

    MainAthenaFactory maFactory;

    @BeforeEach
    void setUp() {
        maFactory = new MainAthenaFactory();
    }


    @Test
    void TestAthenaSetup() {
        MatcherAssert.assertThat("Should not be null", null, notNullValue());
    }
}
