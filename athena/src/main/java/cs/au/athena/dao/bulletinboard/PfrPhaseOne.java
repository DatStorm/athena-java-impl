package cs.au.athena.dao.bulletinboard;

import java.util.ArrayList;
import java.util.List;

public class PfrPhaseOne extends ArrayList<PfrPhaseOne.Entry> {
    public PfrPhaseOne(int size) {
        super(size);
    }

    public static class Entry {
        Integer index;
        List<CombinedCiphertextAndProof> ciphertextAndProof;

        public Entry(Integer index, List<CombinedCiphertextAndProof> ciphertextAndProof) {
            this.index = index;
            this.ciphertextAndProof = ciphertextAndProof;
        }

        public Integer getIndex() {
            return index;
        }

        public List<CombinedCiphertextAndProof> getCombinedCiphertextAndProof() {
            return ciphertextAndProof;
        }
    }
    /*

    public List<Ciphertext> getCiphertexts(int entryIndex) {
        return this.get(entryIndex).getRight().stream()
                .map(CombinedCiphertextAndProof::getCombinedCiphertext)
                .collect(Collectors.toList());
    }
     */


}
