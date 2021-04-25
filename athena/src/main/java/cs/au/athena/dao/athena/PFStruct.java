package cs.au.athena.dao.athena;

import cs.au.athena.dao.mixnet.MixBallot;
import cs.au.athena.dao.mixnet.MixProof;

import java.util.ArrayList;
import java.util.List;

//Responsible for holding all Athena proofs
public class PFStruct {
    public final List<PFRStruct> pfr;
    public final List<MixBallot> mixBallotList;
    public final MixProof mixProof;
    public final List<PFDStruct> pfd;


    public PFStruct(List<PFRStruct> pfr, List<MixBallot> mixBallotList, List<PFDStruct> pfd, MixProof mixProof) {
        this.pfr = pfr;
        this.mixBallotList = mixBallotList;
        this.pfd = pfd;
        this.mixProof = mixProof;
    }

}
