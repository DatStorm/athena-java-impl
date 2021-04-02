package project.dao.athena;

import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixProof;

import java.util.List;

public class PFStruct {
    public final List<PFRStruct> pfr;
    public final List<MixBallot> mixBallotList;
    public final List<PFDStruct> pfd;
    public final MixProof mixProof;


    public PFStruct(List<PFRStruct> pfr, List<MixBallot> mixBallotList, List<PFDStruct> pfd, MixProof mixProof) {
        this.pfr = pfr;
        this.mixBallotList = mixBallotList;
        this.pfd = pfd;
        this.mixProof = mixProof;
    }
}
