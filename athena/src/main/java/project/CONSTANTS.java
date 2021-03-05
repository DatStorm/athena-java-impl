package project;


public class CONSTANTS {

//    public static final int ELGAMAL_BIT_LENGTH = 2048; //SECURE
//    public static final int ELGAMAL_BIT_LENGTH = 2048/4;
//    public static final int ELGAMAL_BIT_LENGTH = 8;
    public static final int ELGAMAL_BIT_LENGTH = 1024;
    public static final int KAPPA = ELGAMAL_BIT_LENGTH;
    public static final long RANDOM_SEED = 2;
    public static final String ALGORITHM_SHA3_256 = "SHA3-256";
    public static final int MIXNET_N = 256;

    
    
    
    

    /**
     * OLD ONES NOT USED ANY MORE
     */
    public static final int SIGMA2_EL_SECURITY_PARAM_T = 128; // suggested old is 80
    public static final int SIGMA2_EL_SECURITY_PARAM_L = 40; // FIXME: should properly be somewhat larger!!!
    public static final int SIGMA2_EL_SECURITY_PARAM_S1 = 40; // FIXME: should properly be somewhat larger!!!. Look at article for why these numbers
    public static final int SIGMA2_EL_SECURITY_PARAM_S2 = 552;// FIXME: should properly be somewhat larger!!!. Look at article for why these numbers
    public static final long SIGMA2_SECURITY_PARAM_k1 = 320;
    public static final long SIGMA2_SECURITY_PARAM_k2 = 2048;
}
