package cs.au.athena.distributed;

import cs.au.athena.CONSTANTS;
import cs.au.athena.athena.strategy.Strategy;
import cs.au.athena.athena.AthenaImpl;
import cs.au.athena.dao.athena.ElectionSetup;
import cs.au.athena.elgamal.ElGamalSK;
import cs.au.athena.elgamal.Group;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.factory.MainAthenaFactory;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;


@Tag("TestAthenaDistributedStrategy")
@DisplayName("Test Athena Distributed Strategy")
public class TestAthenaDistributedStrategy {
    private final int kappa = CONSTANTS.KAPPA;
    private final int nc = CONSTANTS.NUMBER_OF_CANDIDATES_DEFAULT;
    MainAthenaFactory maFactory;

    @BeforeEach
    void setUp() {
        maFactory = new MainAthenaFactory(AthenaFactory.STRATEGY.DISTRIBUTED);
    }


    @Test
    void TestAthenaSetup() {
        AthenaImpl athena = new AthenaImpl(maFactory);
        ElectionSetup setup = athena.Setup(nc, kappa);
        MatcherAssert.assertThat("Should not be null", setup.sk, notNullValue());
    }

    @Test
    void TestGetElGamalSK() {
        Strategy strategy = maFactory.getStrategy();
        Random random = maFactory.getRandom();
        Group group = strategy.getGroup(kappa * 8 , random);

        // Should post stuff
        ElGamalSK sk = strategy.getElGamalSK(0, group, random);
        // Get g^P(X)


        MatcherAssert.assertThat("Should not be null", sk, is(true));
    }
}
