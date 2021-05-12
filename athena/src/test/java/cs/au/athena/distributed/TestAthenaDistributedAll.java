package cs.au.athena.distributed;

import org.junit.jupiter.api.Tag;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;


@RunWith(JUnitPlatform.class)
@Tag("TestAthenaDistributed")
@SelectClasses({
        TestAthenaDistributed.class,
        TestAthenaDistributedWith3Talliers.class,
})
public class TestAthenaDistributedAll {
}

