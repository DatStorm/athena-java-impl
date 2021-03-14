package project.athena;

import project.dao.athena.PFStruct;
import project.dao.athena.PK_Vector;
import project.dao.sigma1.PublicInfoSigma1;
import project.elgamal.Ciphertext;
import project.sigma.Sigma1;

import java.math.BigInteger;
import java.util.Map;

public class AthenaCommon {

    public static boolean verifyKey(Sigma1 sigma1, PK_Vector pkv, int kappa) {
        return sigma1.VerifyKey(new PublicInfoSigma1(kappa, pkv.pk), pkv.rho, kappa);
    }

    public static boolean parsePKV(PK_Vector pkv) {
        return pkv != null && pkv.rho != null && pkv.pk != null;
    }

    // Check all values if hashmap is equal to x.
    public static boolean valuesAreAllX(Map<BigInteger, Integer> map, Integer x){
        for (Integer i : map.values()) {
            if (!x.equals(i)) {
                System.out.println("found a deviating value");
                return false;
            }
        }
        return true;
    }

    public static Ciphertext homoCombination(Ciphertext cipherText, BigInteger n, BigInteger p) {
        return cipherText.modPow(n, p);
    }

    public static boolean parsePF(PFStruct pf) {
        return pf != null && pf.pfd != null && pf.mixBallotList != null && pf.pfr != null;
    }


}
