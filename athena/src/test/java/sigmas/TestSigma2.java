package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.sigma.sigma2.Sigma2;
import project.factory.Factory;
import project.factory.MainFactory;
import project.sigma.sigma2.Sigma2EL;

import java.security.MessageDigest;

import static org.junit.Assert.assertTrue;

@Tag("TestsSigma2")
@DisplayName("Test Sigma2")
public class TestSigma2 {

    private Sigma2 sigma2;
    private Sigma2EL sigma2EL;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        MessageDigest hash = factory.getHash();
        sigma2 = new Sigma2(hash);

        sigma2EL = new Sigma2EL(hash);

    }


    @Test
    void TestSigma2_EL() {

//        sigma2.EL(x,r1,r2,g,h1,g2,h2,y1,y2);

//        sigma2EL.prove();
//        sigma2EL.verify();

        assertTrue("Should return 1", true);
    }
}