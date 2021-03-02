package project.dao.athena;

import project.dao.mixnet.MixBallot;

import java.util.List;

public class PFStruct {
    public final List<PFRStruct> pfr;
    public final List<MixBallot> b;
    public final List<PFDStruct> pfd;

    public PFStruct(List<PFRStruct> pfr, List<MixBallot> B, List<PFDStruct> pfd) {
        this.pfr = pfr;
        this.b = B;
        this.pfd = pfd;
    }
}
