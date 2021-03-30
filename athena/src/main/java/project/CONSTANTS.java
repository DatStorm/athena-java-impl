package project;


import java.math.BigInteger;

public class CONSTANTS {
    public static final long RANDOM_SEED = 2;
    public static final String ALGORITHM_SHA3_256 = "SHA3-256";
    public static final int NUMBER_OF_CANDIDATES_DEFAULT = 10;



    /**
     * Security parameters
     */
    public static final int KAPPA =  ELGAMAL_CURRENT.ELGAMAL_BIT_LENGTH / 8;

    // Note that nc = MSG_SPACE_LENGTH
    public static final int MSG_SPACE_LENGTH = 1000; // for testing purposes only. Needed when testing individual aspects of Athena

    
    public static final BigInteger BULLET_PROOF_R = BigInteger.ZERO;


    public static class ELGAMAL_CURRENT {
        public static final BigInteger ELGAMAL_P = ELGAMAL_1024_BITS.ELGAMAL_P;
        public static final BigInteger ELGAMAL_Q = ELGAMAL_1024_BITS.ELGAMAL_Q;
        public static final BigInteger ELGAMAL_G = ELGAMAL_1024_BITS.ELGAMAL_G;

        /**
         * Elgamal bit length specify how big values to use.
         */
        public static final int ELGAMAL_BIT_LENGTH = ELGAMAL_1024_BITS.ELGAMAL_BIT_LENGTH;
//        public static final BigInteger FAKE_SK = ELGAMAL_1024_BITS.FAKE_SK;
    }


    /**
     * Fixed values for the case when elGamal with 64 bits is used.
     */
    public static class ELGAMAL_32_BITS {
        public static final int ELGAMAL_BIT_LENGTH = 32;
        public static final BigInteger ELGAMAL_P = new BigInteger("7951924187");
        public static final BigInteger ELGAMAL_Q = new BigInteger("3975962093");
        public static final BigInteger ELGAMAL_G = new BigInteger("3849857299");
        public static final BigInteger FAKE_SK = new BigInteger("963783867");
    }


    /**
     * Fixed values for the case when elGamal with 64 bits is used.
     */
    public static class ELGAMAL_64_BITS {
        public static final int ELGAMAL_BIT_LENGTH = 64;
        public static final BigInteger ELGAMAL_P = new BigInteger("33104598056928515207");
        public static final BigInteger ELGAMAL_Q = new BigInteger("16552299028464257603");
        public static final BigInteger ELGAMAL_G = new BigInteger("25068689957054747570");
    }


    /**
     * Fixed values for the case when elGamal with 1024 bits is used.
     */
    public static class ELGAMAL_1024_BITS {
        public static final int ELGAMAL_BIT_LENGTH = 1024;
        public static final BigInteger ELGAMAL_P = new BigInteger("203563861925565177933951527681865992552429014002237425191410266898486184182026619996987894353762119957056230747716582757205994486135986076638697536841048852140992609316787978027688024528962704074922913310302293967528294897853920568227642592344438342607588008139227413464161980201861673136375912646999611663087");
        public static final BigInteger ELGAMAL_Q = new BigInteger("101781930962782588966975763840932996276214507001118712595705133449243092091013309998493947176881059978528115373858291378602997243067993038319348768420524426070496304658393989013844012264481352037461456655151146983764147448926960284113821296172219171303794004069613706732080990100930836568187956323499805831543");
        public static final BigInteger ELGAMAL_G = new BigInteger("1844215720087197381744494932667834995394592854090000269565019288241668468229931410777742064942636776445825219224117373251985570793034245911908637548366552981960421195704530326918084242971835539836821340557428309723513510836056755747806132206209220185984626592005964560631795631069575371181435232772937697315");
    }


    /**
     * COLORS
     */
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";


    //    public static final int ELGAMAL_BIT_LENGTH = 2048; //SECURE
//    public static final int ELGAMAL_BIT_LENGTH = 2048/4;
//    public static final int ELGAMAL_BIT_LENGTH = 8;
//    public static final int KAPPA = 8;


}


//    OLD NOT USED ANYMORE
//    public static final int SIGMA2_EL_SECURITY_PARAM_T = 128;   // suggested
//    public static final int SIGMA2_EL_SECURITY_PARAM_L = 40;    // suggested
//    public static final int SIGMA2_EL_SECURITY_PARAM_S1 = 40;   // suggested
//    public static final int SIGMA2_EL_SECURITY_PARAM_S2 = 552;  // suggested
//    public static final long SIGMA2_SECURITY_PARAM_k1 = 320;    // suggested
//    public static final long SIGMA2_SECURITY_PARAM_k2 = 2048;   // suggested