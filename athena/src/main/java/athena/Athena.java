package athena;

import project.dao.athena.*;

public interface Athena {
    ElectionSetup Setup(int nc,int kappa);
    RegisterStruct Register(PK_Vector pkv, int kappa);
    Ballot Vote(CredentialTuple dv, PK_Vector pkv, int vote, int cnt, int nc, int kappa);
    TallyStruct Tally(SK_Vector skv,  int nc, int kappa);
    boolean Verify(PK_Vector pkv, int kappa);
}
