package project.athena;


import project.dao.KAPPA_PK_M;
import project.dao.SK_R;
import project.dao.sigma1.ProofKeyInfo;

import java.util.ArrayList;

public class Sigma1 {

    //input pk, sk,
    public ProofKeyInfo ProveKey(KAPPA_PK_M kappa_pk_m, SK_R sk_r, int kappa) {

        ArrayList ei = new ArrayList<Integer>();



        return new ProofKeyInfo();
    }

    public boolean VerKey(KAPPA_PK_M kappa_pk_m, ProofKeyInfo rho, int kappa){
        return false;
    }
}