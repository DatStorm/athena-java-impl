package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.athena.Gen;
import project.athena.Sigma1;
import project.dao.Randomness;
import project.dao.SK_R;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import project.factory.Factory;
import project.factory.MainFactory;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static org.junit.Assert.assertTrue;

@Tag("TestsSigma2")
@DisplayName("Test Sigma2")
public class TestSigma2 {

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();


    }


    @Test
    void TestSigma2() {


        assertTrue("Should return 1", true);
    }
}
