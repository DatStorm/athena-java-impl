package cs.au.athena.dao.bulletinboard;


import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;

public class PfrPhaseOne extends ArrayList<Pair<Integer, List<CombinedCiphertextAndProof>>> {
    public PfrPhaseOne(int size) {
        super(size);
    }

}
