package project.dao.athena;

import project.dao.mixnet.MixBallot;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class TallyStruct {
    public final Map<BigInteger, Integer> votes_b;
    public final PFStruct pf;

    public TallyStruct(Map<BigInteger, Integer> votes_B, PFStruct pf) {
        this.votes_b = votes_B;
        this.pf = pf;
    }
}
