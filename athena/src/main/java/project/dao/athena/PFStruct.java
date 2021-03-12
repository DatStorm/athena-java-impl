package project.dao.athena;

import project.dao.mixnet.MixBallot;

import java.util.List;

public class PFStruct {
    public final List<PFRStruct> pfr;
    public final List<MixBallot> mixBallotList;
    public final List<PFDStruct> pfd;

    public PFStruct(List<PFRStruct> pfr, List<MixBallot> mixBallotList, List<PFDStruct> pfd) {
        this.pfr = pfr;
        this.mixBallotList = mixBallotList; 
        this.pfd = pfd;
    }
}
