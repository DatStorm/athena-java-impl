package project.athena;

import project.dao.athena.*;

import java.math.BigInteger;
import java.util.Map;

public interface Athena {
    ElectionSetup Setup(int kappa, int nc);
    RegisterStruct Register(PK_Vector pkv);
    Ballot Vote(CredentialTuple dv, PK_Vector pkv, int vote, int cnt, int nc);
    TallyStruct Tally(SK_Vector skv,  int nc);
    boolean Verify(PK_Vector pkv, int nc,  Map<Integer, Integer> b, PFStruct pf);
}
