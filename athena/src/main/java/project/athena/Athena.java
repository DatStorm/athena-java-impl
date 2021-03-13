package project.athena;

import project.dao.athena.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;

public interface Athena {

    SetupStruct Setup(int kappa) throws IOException;
    RegisterStruct Register(PK_Vector pkv, int kappa);
    Ballot Vote(CredentialTuple dv, PK_Vector pkv, int vote, int cnt, int nc, int kappa);
    TallyStruct Tally(SK_Vector skv, BulletinBoard bb, int nc,  int kappa);
    boolean Verify(PK_Vector pkv, BulletinBoard bb, int nc,  Map<BigInteger, Integer> b, PFStruct pf, int kappa);
}
