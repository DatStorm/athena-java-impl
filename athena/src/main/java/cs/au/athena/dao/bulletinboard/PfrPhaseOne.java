package cs.au.athena.dao.bulletinboard;


import cs.au.athena.elgamal.Ciphertext;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class PfrPhaseOne extends ArrayList<Pair<Integer, List<CombinedCiphertextAndProof>>> {
    public PfrPhaseOne(int size) {
        super(size);
    }

    public List<Ciphertext> getCiphertexts(int entryIndex) {
        return this.get(entryIndex).getRight().stream()
                .map(CombinedCiphertextAndProof::getCombinedCiphertext)
                .collect(Collectors.toList());
    }
}
