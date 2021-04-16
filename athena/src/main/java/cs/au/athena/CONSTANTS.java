package cs.au.athena;

import cs.au.athena.elgamal.Group;

import java.math.BigInteger;

public class CONSTANTS {
    public static final long RANDOM_SEED = 2;
    public static final String ALGORITHM_SHA3_256 = "SHA3-256";
    public static final int NUMBER_OF_CANDIDATES_DEFAULT = 10;


    /**
     * Security parameters
     */
    public static final int KAPPA = ELGAMAL_CURRENT.ELGAMAL_BIT_LENGTH / 8;

    // Note that nc = MSG_SPACE_LENGTH
    public static final int MSG_SPACE_LENGTH = 1000; // for testing purposes only. Needed when testing individual aspects of Athena


    public static final BigInteger BULLET_PROOF_R = BigInteger.ZERO;


    public static class ELGAMAL_CURRENT {
        public static final BigInteger ELGAMAL_P = ELGAMAL_2048_BITS.ELGAMAL_P;
        public static final BigInteger ELGAMAL_Q = ELGAMAL_2048_BITS.ELGAMAL_Q;
        public static final BigInteger ELGAMAL_G = ELGAMAL_2048_BITS.ELGAMAL_G;

        /**
         * Elgamal bit length specify how big values to use.
         */
        public static final int ELGAMAL_BIT_LENGTH = ELGAMAL_2048_BITS.ELGAMAL_BIT_LENGTH;
        public static final Group GROUP = new Group(ELGAMAL_P, ELGAMAL_Q, ELGAMAL_G);

    }


    /**
     * Fixed values for the case when elGamal with 64 bits is used.
     */
    private static class ELGAMAL_32_BITS {
        public static final int ELGAMAL_BIT_LENGTH = 32;
        public static final BigInteger ELGAMAL_P = new BigInteger("7951924187");
        public static final BigInteger ELGAMAL_Q = new BigInteger("3975962093");
        public static final BigInteger ELGAMAL_G = new BigInteger("3849857299");
        public static final BigInteger FAKE_SK = new BigInteger("963783867");
    }


    /**
     * Fixed values for the case when elGamal with 64 bits is used.
     */
    private static class ELGAMAL_64_BITS {
        public static final int ELGAMAL_BIT_LENGTH = 64;
        public static final BigInteger ELGAMAL_P = new BigInteger("33104598056928515207");
        public static final BigInteger ELGAMAL_Q = new BigInteger("16552299028464257603");
        public static final BigInteger ELGAMAL_G = new BigInteger("25068689957054747570");
    }


    /**
     * Fixed values for the case when elGamal with 1024 bits is used.
     */
    private static class ELGAMAL_1024_BITS {
        public static final int ELGAMAL_BIT_LENGTH = 1024;
        public static final BigInteger ELGAMAL_P = new BigInteger("203563861925565177933951527681865992552429014002237425191410266898486184182026619996987894353762119957056230747716582757205994486135986076638697536841048852140992609316787978027688024528962704074922913310302293967528294897853920568227642592344438342607588008139227413464161980201861673136375912646999611663087");
        public static final BigInteger ELGAMAL_Q = new BigInteger("101781930962782588966975763840932996276214507001118712595705133449243092091013309998493947176881059978528115373858291378602997243067993038319348768420524426070496304658393989013844012264481352037461456655151146983764147448926960284113821296172219171303794004069613706732080990100930836568187956323499805831543");
        public static final BigInteger ELGAMAL_G = new BigInteger("1844215720087197381744494932667834995394592854090000269565019288241668468229931410777742064942636776445825219224117373251985570793034245911908637548366552981960421195704530326918084242971835539836821340557428309723513510836056755747806132206209220185984626592005964560631795631069575371181435232772937697315");
    }

    /**
     * Fixed values for the case when elGamal with 1024 bits is used.
     */
    public static class ELGAMAL_2048_BITS {
        public static final int ELGAMAL_BIT_LENGTH = 2048;
        public static final BigInteger ELGAMAL_P = new BigInteger("47850609090699997627879442079015559789588810016055085168663231680945325877494096894836476154799550171424808356249458404121371315263116668236418222475422071961476894752261421260596367647031226200967811492818532601173527342915089064808184064551907831145903240847672032724074553103869462163366969831462702161952339872821129660806573472523877253285641013859085880500714801660319907463822794201026664417879512132313854942310349732663354343626019002558115211494182178301599918876261929956636508988052436521635330562118747434513092371287210613234391194644549015352548054893600662716724937082732576955374941850075721889421963");
        public static final BigInteger ELGAMAL_Q = new BigInteger("23925304545349998813939721039507779894794405008027542584331615840472662938747048447418238077399775085712404178124729202060685657631558334118209111237711035980738447376130710630298183823515613100483905746409266300586763671457544532404092032275953915572951620423836016362037276551934731081683484915731351080976169936410564830403286736261938626642820506929542940250357400830159953731911397100513332208939756066156927471155174866331677171813009501279057605747091089150799959438130964978318254494026218260817665281059373717256546185643605306617195597322274507676274027446800331358362468541366288477687470925037860944710981");
        public static final BigInteger ELGAMAL_G = new BigInteger("22928822524553592325343836897579982613476702112524283072913975990479376911485385690390713695956551732484846013086144100276708750662196461102671975930622227856670956528360854328719303544806474284891937049819824988051076150578577122204492619128894351284922310793772437872499329344622709685455212993974080481845672911367973954551798928044766388268357039319325651579931765376343767195022939562915775807163827759912291303708734156215265823145454438086988237230810896265398453020092295253015606657879597710074126191913706626927000106051300642904887064077525555094961629360958048703767582795601859785856621468686929397503311");
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

    /***************************************************
     *                 Single tally                    *
     **************************************************/
    public static final int TALLIER_INDEX = 0;

    /***************************************************
     *             Distributed tally                   *
     **************************************************/
    public static class TALLIER_CURRENT {
        public static final int TALLIER_COUNT = TALLIER_10.TALLIER_COUNT;
        public static final int K = TALLIER_10.K;
    }

    private static class TALLIER_10 {
        public static final int TALLIER_COUNT = 10;
        public static final int K = (TALLIER_COUNT/2) - 1 ; // k < n/2
    }




}

