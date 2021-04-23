package cs.au.athena.dao.bulletinboard;

import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;

public class PfrPhaseTwo extends ArrayList<Pair<Integer, List<DecryptionShareAndProof>>> {
    public PfrPhaseTwo(int initialCapacity) {
        super(initialCapacity);
    }
}
