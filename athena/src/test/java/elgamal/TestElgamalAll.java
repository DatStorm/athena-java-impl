package elgamal;


import org.junit.jupiter.api.Tag;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@Tag("TestElgamalAll")
@SelectClasses( {TestElgamal.class, TestElgamalCiphertext.class} )
public class TestElgamalAll {
}
