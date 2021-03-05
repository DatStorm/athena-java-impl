import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.ExcludeTags;
import org.junit.platform.suite.api.IncludeTags;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.runner.RunWith;


@RunWith(JUnitPlatform.class)
@SelectPackages("")
@IncludeTags({
        "TestElgamal",
//        "TestsSigma1", // FIXME: add when done!
        "TestsSigma2BulletProof",
        "TestsSigma3",
        "TestsSigma4",
        "TestsMixnets",
        "TestsCiphertexts",
        "TestsUTIL",
        "TestsAthenaSetup",
        "TestsAthenaRegister",
        "TestsAthenaVote",
        "TestsAthenaTally",
        "TestsAthenaVerify",
})
@ExcludeTags({"TestsSigma2"})
public class TestAll {
}
