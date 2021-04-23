package cs.au.athena.dao.bulletinboard;

import java.util.ArrayList;
import java.util.List;

public class PfrPhaseTwo extends ArrayList<PfrPhaseTwo.Entry> {
    public PfrPhaseTwo(int initialCapacity) {
        super(initialCapacity);
    }

    public static class Entry {
        Integer index;
        List<DecryptionShareAndProof> decryptionShareAndProofs;

        public Entry(Integer index, List<DecryptionShareAndProof> decryptionShareAndProofs) {
            this.index = index;
            this.decryptionShareAndProofs = decryptionShareAndProofs;
        }

        public Integer getIndex() {
            return index;
        }

        public List<DecryptionShareAndProof> getDecryptionShareAndProofs() {
            return decryptionShareAndProofs;
        }
    }
}
