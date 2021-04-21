package cs.au.athena.athena;

import cs.au.athena.dao.athena.PFStruct;
import cs.au.athena.dao.athena.PK_Vector;
import cs.au.athena.elgamal.Ciphertext;
import cs.au.athena.elgamal.Group;

import java.math.BigInteger;
import java.util.Map;

public class AthenaCommon {


    public static boolean parsePKV(PK_Vector pkv) {
        return pkv != null && pkv.rho != null && pkv.pk != null;
    }

    // Check all values if hashmap is equal to x.
    public static boolean valuesAreAllX(Map<Integer, Integer> map, Integer x){
        for (Integer i : map.values()) {
            if (!x.equals(i)) {
                System.out.println("found a deviating value");
                return false;
            }
        }
        return true;
    }

    public static Ciphertext homoCombination(Ciphertext cipherText, BigInteger n, Group group) {
        return cipherText.modPow(n, group.p);
    }

    public static boolean parsePF(PFStruct pf) {
        return pf != null && pf.pfd != null && pf.mixBallotList != null && pf.pfr != null;
    }


}
