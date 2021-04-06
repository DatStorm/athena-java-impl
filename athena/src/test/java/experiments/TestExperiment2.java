package experiments;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestExperiment2 {

    @BeforeEach
    public void setUp() {

    }

    @Test
    public void TestExperimentTime1Voters() {
        //Vote 1 times
        int numVoters = 1;
        assertThat("We ?", numVoters, is(1));
    }


}
