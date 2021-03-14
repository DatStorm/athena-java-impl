package project.athena;

import project.dao.athena.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;

public interface Athena {

    SetupStruct Setup(int kappa) throws IOException;
    RegisterStruct Register(PK_Vector pkv);
    Ballot Vote(CredentialTuple dv, PK_Vector pkv, int vote, int cnt, int nc);
    TallyStruct Tally(SK_Vector skv,  int nc);
    boolean Verify(PK_Vector pkv, int nc,  Map<BigInteger, Integer> b, PFStruct pf);
}
