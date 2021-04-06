package experiments;

import entities.TestAthenaMaliciousTallier;
import org.junit.jupiter.api.Tag;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;


@RunWith(JUnitPlatform.class)
@Tag("TestExperiments")
@SelectClasses( {TestExperiment1.class, TestExperiment2.class} )
public class TestExperiments {
}
