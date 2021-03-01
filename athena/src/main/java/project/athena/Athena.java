package project.athena;

import project.dao.athena.D_Vector;
import project.dao.athena.PK_Vector;
import project.dao.athena.RegisterStruct;
import project.dao.athena.SetupStruct;

import java.io.IOException;

public interface Athena {

    SetupStruct Setup(int kappa) throws IOException;
    RegisterStruct Register(PK_Vector pkv, int kappa);
    void Vote(D_Vector dv, PK_Vector pkv, int vote, int cnt, int nc, int kappa);
    void Tally();
    void Verify();
}
