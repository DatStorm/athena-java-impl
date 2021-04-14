package cs.au.athena.dao.athena;

import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;

import java.util.ArrayList;
import java.util.List;

public class PFStruct {
    public final List<PFRStruct> pfr;
    public final List<BallotList> mixBallots;
    public final List<MixProof> mixProofs;
    public final List<PFDStruct> pfd;


    public PFStruct(int tallierCount) {
        this.pfr = new ArrayList<>(tallierCount);
        this.mixBallots = new ArrayList<>(tallierCount);
        this.mixProofs = new ArrayList<>(tallierCount);
        this.pfd = new ArrayList<>(tallierCount);

        // Init it all
        for (int i = 0; i < tallierCount; i++) {
            pfr.add(new PFRStruct());
            pfd.add(new PFDStruct());
        }
    }
}
