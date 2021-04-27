
import cs.au.athena.athena.TestAthena;
import cs.au.athena.bulletproof.TestBulletProofs;
import cs.au.athena.elgamal.TestElgamalAll;
import cs.au.athena.sigma.mixnet.TestMixnet;
import cs.au.athena.sigmas.TestSigmas;
import cs.au.athena.util.TestUTIL;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        TestAthena.class,
        TestBulletProofs.class,
        TestElgamalAll.class,
//        TestEntities.class,
//        TestExperiments.class,
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