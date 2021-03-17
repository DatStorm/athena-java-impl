import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.ExcludeTags;
import org.junit.platform.suite.api.IncludeTags;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectPackages("")
@IncludeTags({
        "TestElgamal",
        // FIXME: add when done!
//        "TestsSigma1",
//        "TestsSigma2BulletProof",
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
//@ExcludeTags({""})
public class TestAll {
}

