package sigmas;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.CONSTANTS;
import project.UTIL;
import elgamal.ElGamalSK;
import project.sigma.Sigma1;
import project.dao.*;
import project.dao.sigma1.CoinFlipInfo;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import elgamal.ElGamalPK;
import project.factory.Factory;
import project.factory.MainFactory;


import java.math.BigInteger;
import java.util.ArrayList;

import static org.junit.Assert.*;
//import java.util.SecureRandom;

@Tag("TestsSigma1")
@DisplayName("Test Sigma1")
public class TestSigma1 {
    private final int kappa = CONSTANTS.KAPPA;
    private Sigma1 sigma1;
    private ElGamalSK sk;
    private ElGamalPK pk;
    private Randomness randomness;

    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        this.sk = factory.getSK();
        this.pk = factory.getPK();
        this.sigma1 = new Sigma1();
        this.randomness = new Randomness(123);
    }

  

    @Test
    void TestBigIntegerMod2_IntValueExact() {

        BigInteger one = BigInteger.ONE;
        boolean modedBit = one.mod(BigInteger.TWO).intValueExact() == 1;
        assertTrue("should be 1 % 2 = 1", modedBit);

        BigInteger zero = BigInteger.ZERO;
        boolean zero_modedBit = zero.mod(BigInteger.TWO).intValueExact() == 1;
        assertFalse("should be 0 % 2 = 0", zero_modedBit);


        BigInteger ten = BigInteger.valueOf(10);
        boolean ten_modedBit = ten.mod(BigInteger.TWO).intValueExact() == 1;
        assertFalse("should be 10 % 2 = 0", ten_modedBit);

        BigInteger twentyOne = BigInteger.valueOf(21);
        boolean twentyOne_modedBit = twentyOne.mod(BigInteger.TWO).intValueExact() == 1;
        assertTrue("should be 21 % 2 = 1", twentyOne_modedBit);
    }

    /**
     * Verifying the coinflip protocol.
     * f ?=? F(r,b_A)
     */
    @Test
    void TestProveKey_Verify_step2()  {
        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, this.pk);
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk, randomness, this.kappa);
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = rho.getCoinFlipInfoPairs();
        boolean verify = sigma1.checkStep2(coinFlipInfo_pairs);
        assertTrue("fi ?=? F_i(ri,b_A_i)", verify);
    }

    @Test
    void TestProveKey_Verify_step3()  {
        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, this.pk);
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk, randomness, this.kappa);
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = rho.getCoinFlipInfoPairs();
        ArrayList<BigInteger> s1_sk = rho.getS1_Sk();
        ArrayList<BigInteger> y1_yk = rho.getY1_Yk();

        // index j
        int j = UTIL.findFirstOne(coinFlipInfo_pairs, 1); // find index j

        // bigints g,p,yj
        BigInteger g = publicInfoSigma1.getPK().getGroup().getG();
        BigInteger p = publicInfoSigma1.getPK().getGroup().getP();
        BigInteger yj = y1_yk.get(j);

        boolean verify = sigma1.checkStep3(coinFlipInfo_pairs, s1_sk, y1_yk, g, p, yj);
        assertTrue("bi=0 g^si = yi :: bi=1 g^si = yiyj^-1", verify);
    }

    @Test
    void TestProveKey_Verify_step4()  {
        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, this.pk);
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk, randomness, this.kappa);
        ArrayList<CoinFlipInfo> coinFlipInfo_pairs = rho.getCoinFlipInfoPairs();
        ArrayList<BigInteger> s1_sk = rho.getS1_Sk();
        ArrayList<BigInteger> y1_yk = rho.getY1_Yk();

        // index j
        int j = UTIL.findFirstOne(coinFlipInfo_pairs, 1); // find index j

        // bigints g,p,h,yj,zeta
        BigInteger g = publicInfoSigma1.getPK().getGroup().getG();
        BigInteger p = publicInfoSigma1.getPK().getGroup().getP();
        BigInteger h = publicInfoSigma1.getPK().getH();
        BigInteger yj = y1_yk.get(j);
        BigInteger zeta = rho.getZeta();

        boolean verify = sigma1.checkStep4(g, h, p, yj, zeta);
        assertTrue("g^zeta ?=? hy_j^-1", verify);
    }






    @Test
    void TestProveKey_Verify() {
        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, pk);
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk, randomness, this.kappa);
        boolean verification = sigma1.VerifyKey(publicInfoSigma1, rho, this.kappa);
        assertTrue("Should return 1", verification);
    }



    @Test
    void TestSigma1()  {
        PublicInfoSigma1 publicInfoSigma1 = new PublicInfoSigma1(this.kappa, this.pk);
        ProveKeyInfo rho = sigma1.ProveKey(publicInfoSigma1, this.sk, randomness, this.kappa);
        boolean verification = sigma1.VerifyKey(publicInfoSigma1, rho, this.kappa);
        assertTrue("Should return 1", verification);
    }


}
