
import org.junit.jupiter.api.BeforeEach;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.ExcludeTags;
import org.junit.platform.suite.api.IncludeTags;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.runner.RunWith;
import project.athena.Gen;
import project.athena.Sigma1;
import project.dao.Randomness;
import project.dao.SK_R;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

@RunWith(JUnitPlatform.class)
@SelectPackages("")
@IncludeTags({
        "TestElgamal",
        "TestsSigma1",
        "TestsSigma2",
        "TestsSigma3",
        "TestsSigma4",
//        "TestObliviousTransfer",
//        "offline.TestBitMatrix",
//        "offline.TestEncryption"
})
//@ExcludeTags({"BenchmarkSender", "BenchmarkReceiver"})
public class TestAll {
}
