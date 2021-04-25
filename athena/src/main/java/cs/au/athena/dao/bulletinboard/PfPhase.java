package cs.au.athena.dao.bulletinboard;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

// Keeps a list of CompletableFuture<Entry>
public class PfPhase<T> {
    List<CompletableFuture<Entry<T>>> entries;
    int nextIncompleteEntry = 0;

    public PfPhase(int size) {
        entries =  new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            entries.add(new CompletableFuture<>());
        }
    }

    public boolean add(Entry<T> entry) {
        return entries.get(nextIncompleteEntry++).complete(entry);
    }

    public CompletableFuture<Entry<T>> getFuture(int i) {
        return entries.get(i);
    }

    public Entry<T> get(int i) {
        return entries.get(i).join();
    }

    public List<Entry<T>> getAll() {
        return entries.stream().map(CompletableFuture::join).collect(Collectors.toList());
    }

    public int size() {
        return entries.size();
    }

}
