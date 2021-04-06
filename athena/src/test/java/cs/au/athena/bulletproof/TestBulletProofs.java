package cs.au.athena.bulletproof;

import org.junit.jupiter.api.Tag;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@Tag("TestBulletProofs")
@SelectClasses( {TestBulletProof.class, TestBulletProofInvalid.class} )
public class TestBulletProofs {
}
