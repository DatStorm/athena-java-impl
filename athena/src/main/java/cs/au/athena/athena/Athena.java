package cs.au.athena.athena;

import cs.au.athena.dao.athena.*;
import cs.au.athena.elgamal.ElGamalSK;

import java.util.Map;

public interface Athena {
    ElGamalSK Setup(int tallierIndex, int nc, int kappa);
    RegisterStruct Register(int kappa);
    Ballot Vote(CredentialTuple dv, int vote, int cnt, int nc, int kappa);
    Map<Integer, Integer> Tally(int tallierIndex, ElGamalSK skShare, int nc, int kappa);
    boolean Verify( int kappa);
}
