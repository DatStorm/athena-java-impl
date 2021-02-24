import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.ExcludeTags;
import org.junit.platform.suite.api.IncludeTags;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.runner.RunWith;


@RunWith(JUnitPlatform.class)
@SelectPackages("")
@IncludeTags({
        "TestElgamal",
//        "TestsSigma1",
        "TestsSigma2",
        "TestsSigma3",
        "TestsSigma4",
        "TestsMixnets",
        "TestsCiphertexts",
        "TestsUTIL",
//        "TestObliviousTransfer",
})
@ExcludeTags({"TestsSigma1"})
public class TestAll {
}
