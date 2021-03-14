package project.dao.athena;

import java.math.BigInteger;
import java.util.Map;

public class TallyStruct {
    public final Map<BigInteger, Integer> tallyOfVotes;
    public final PFStruct pf;

    public TallyStruct(Map<BigInteger, Integer> tallyOfVotes, PFStruct pf) {
        this.tallyOfVotes = tallyOfVotes;
        this.pf = pf;
    }
}
