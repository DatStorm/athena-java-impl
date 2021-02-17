package project.athena;

import project.dao.sigma3.ProveDecryptionInfo;
import project.dao.sigma3.PublicInfoSigma3;
import project.elgamal.ElGamalSK;

public class Sigma3 {
    // (pk, c', N), sk, k)
    public static void proveDecryption(ProveDecryptionInfo info, ElGamalSK sk, int k) {
        /**
        p
        q
        z=c
        **/

        //foreach

        //random s in Z_q
        //(a,b)= (g^s, m^s)
        //c = hash(a,b,g,h,z,

    }

    public static void verifyDecryption(ProveDecryptionInfo info, PublicInfoSigma3 publicInfo, int k) {

    }

}