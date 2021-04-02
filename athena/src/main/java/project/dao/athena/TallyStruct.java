package project.dao.athena;

import java.math.BigInteger;
import java.util.Map;

public class TallyStruct {
    public final Map<Integer, Integer> tallyOfVotes;
    public final PFStruct pf;

    public TallyStruct(Map<Integer, Integer> officialTally, PFStruct pf) {
        this.tallyOfVotes = officialTally;
        this.pf = pf;
    }
}
