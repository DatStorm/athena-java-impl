package cs.au.athena.sigmas;


import cs.au.athena.entities.TestAthenaMaliciousTallier;
import org.junit.jupiter.api.Tag;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@Tag("TestSigmas")
@SelectClasses({TestSigma1.class, TestSigma2Pedersen.class, TestSigma3.class, TestSigma4.class})
public class TestSigmas {
}
