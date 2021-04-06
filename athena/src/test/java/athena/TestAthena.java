package athena;

import org.junit.jupiter.api.Tag;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;


@RunWith(JUnitPlatform.class)
@Tag("TestAthena")
@SelectClasses({TestAthenaSetup.class,
        TestAthenaRegister.class,
        TestAthenaVote.class,
        TestAthenaTally.class,
        TestAthenaVerify.class,
})
public class TestAthena {
}

