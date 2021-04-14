package cs.au.athena.athena.distributed;

import cs.au.athena.athena.Athena;
import cs.au.athena.dao.athena.*;
import cs.au.athena.factory.AthenaFactory;

public class AthenaImplDistributed implements Athena {
    private final AthenaFactory athenaFactory;

    public AthenaImplDistributed(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;

    }

    @Override
    public ElectionSetup Setup(int nc, int kappa) {

        return new ElectionSetup(null);
    }

    @Override
    public RegisterStruct Register(PK_Vector pkv, int kappa) {
        return null;
    }

    @Override
    public Ballot Vote(CredentialTuple dv, PK_Vector pkv, int vote, int cnt, int nc, int kappa) {
        return null;
    }

    @Override
    public TallyStruct Tally(SK_Vector skv, int nc, int kappa) {
        return null;
    }

    @Override
    public boolean Verify(PK_Vector pkv, int kappa) {
        return false;
    }
}
