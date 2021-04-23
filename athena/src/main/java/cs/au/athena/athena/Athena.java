package cs.au.athena.athena;

import cs.au.athena.dao.athena.*;
import cs.au.athena.elgamal.ElGamalSK;

import java.util.Map;

public interface Athena {
    ElGamalSK Setup(int tallierIndex, int nc, int kappa);
    RegisterStruct Register(PK_Vector pkv, int kappa);
    Ballot Vote(CredentialTuple dv, PK_Vector pkv, int vote, int cnt, int nc, int kappa);
    Map<Integer, Integer> Tally(int tallierIndex, SK_Vector skv, int nc, int kappa);
    boolean Verify(PK_Vector pkv, int kappa);
}
