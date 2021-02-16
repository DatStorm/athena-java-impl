
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.ExcludeTags;
import org.junit.platform.suite.api.IncludeTags;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectPackages("")
@IncludeTags({"TestsSigma1"
//        "TestBits",
//        "TestObliviousTransfer",
//        "offline.TestBitMatrix",
//        "offline.TestEncryption"
})
//@ExcludeTags({"BenchmarkSender", "BenchmarkReceiver"})
public class TestAll {
}
