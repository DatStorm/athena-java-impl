package sigmas;


import entities.TestAthenaMaliciousTallier;
import org.junit.jupiter.api.Tag;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@Tag("TestSigmas")
@SelectClasses( {TestSigma1.class, TestSigma3.class, TestSigma4.class} )
public class TestSigmas {
}
