package project.athena;

import project.dao.athena.*;

import java.io.IOException;

public interface Athena {

    SetupStruct Setup(int kappa) throws IOException;
    RegisterStruct Register(PK_Vector pkv, int kappa);
    Ballot Vote(D_Vector dv, PK_Vector pkv, int vote, int cnt, int nc, int kappa);
    void Tally();
    void Verify();
}
