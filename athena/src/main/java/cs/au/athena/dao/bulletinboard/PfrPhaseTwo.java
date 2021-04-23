package cs.au.athena.dao.bulletinboard;

import cs.au.athena.elgamal.Ciphertext;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class PfrPhaseTwo extends ArrayList<Pair<Integer, List<DecryptionShareAndProof>>> {
    public PfrPhaseTwo(int initialCapacity) {
        super(initialCapacity);
    }
}
