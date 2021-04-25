package cs.au.athena.dao.bulletinboard;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class PfrPhaseTwo {
    List<CompletableFuture<PfrPhaseTwo.Entry>> entries;
    int nextIncompleteEntry = 0;

    public PfrPhaseTwo(int size) {
        entries =  new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            entries.add(new CompletableFuture<>());
        }
    }

    public boolean add(Entry entry) {
        return entries.get(nextIncompleteEntry++).complete(entry);
    }

    public Entry get(int i) {
        return entries.get(i).join();
    }

    public List<CompletableFuture<Entry>> getEntryFutures() {
        return entries;
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
