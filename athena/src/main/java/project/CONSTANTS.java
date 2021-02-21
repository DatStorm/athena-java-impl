package project;

import java.math.BigInteger;

public class CONSTANTS {

//    public static final int ELGAMAL_BIT_LENGTH = 2048; //SECURE
//    public static final int ELGAMAL_BIT_LENGTH = 2048/4;
//    public static final int ELGAMAL_BIT_LENGTH = 8;
//    public static final int ELGAMAL_BIT_LENGTH = 1024;
    public static final int ELGAMAL_BIT_LENGTH = 128;
    public static final int KAPPA = ELGAMAL_BIT_LENGTH;
    public static final long RANDOM_SEED = 0;
    public static final BigInteger ELGAMAL_RAND_R = BigInteger.valueOf(2);


    public static final int SIGMA2_EL_SECURITY_PARAM_T = 10;
    public static final int SIGMA2_EL_SECURITY_PARAM_L = 10;
    public static final int MIXNET_N = 100;
    public static final String ALGORITHM_SHA3_256 = "SHA3-256";
//    public static final String EL_GAMEL_PK_ = "AMRfIhRxyRxb1Skji4sxwr+BVou2Qbo7sHANN11fvXtP1STuCuVZj+HaoSyrLGigLMhhS/cGA3z5" +
//            "JkvvhBBv5zXj0lhMkG5w9kS5w+KmMkc/2n5W9yYCECyf9I3JbLy7d+yCsTXRGPh+xhVyH/nID5PY" +
//            "yc5OhMVE2sNHCPpFaMl5";
}
