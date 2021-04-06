import athena.TestAthena;
import bulletproof.TestBulletProofs;
import elgamal.TestElgamalAll;
import entities.TestEntities;
import experiments.TestExperiments;
import mixnet.TestMixnet;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import sigmas.TestSigmas;
import util.TestUTIL;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        TestAthena.class,
        TestBulletProofs.class,
        TestElgamalAll.class,
        TestEntities.class,
        TestExperiments.class,
        TestMixnet.class,
        TestSigmas.class,
        TestUTIL.class,
})
public class TestAll {
}




//@RunWith(JUnitPlatform.class)
//@SelectPackages("")
//@IncludeTags({
//        "TestElgamal",
//        // FIXME: add when done!
////        "TestsSigma1",
////        "TestsSigma2BulletProof",
//        "TestsSigma3",
//        "TestEntities",
////        "TestsSigma4",
//        "TestsMixnets",
//        "TestsCiphertexts",
//        "TestsUTIL",
//        "TestsAthenaSetup",
//        "TestsAthenaRegister",
//        "TestsAthenaVote",
//        "TestsAthenaTally",
//        "TestsAthenaVerify",
//})
////@ExcludeTags({""})