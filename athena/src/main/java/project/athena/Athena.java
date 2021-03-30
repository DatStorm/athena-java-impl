package project.athena;

import project.dao.athena.*;

import java.math.BigInteger;
import java.util.Map;

public interface Athena {
    ElectionSetup Setup(int nc,int kappa);
    RegisterStruct Register(PK_Vector pkv, int kappa);
    Ballot Vote(CredentialTuple dv, PK_Vector pkv, int vote, int cnt, int nc, int kappa);
    TallyStruct Tally(SK_Vector skv,  int nc, int kappa);
    boolean Verify(PK_Vector pkv, int nc,  Map<Integer, Integer> b, PFStruct pf, int kappa);
}
