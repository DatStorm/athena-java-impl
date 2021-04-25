package cs.au.athena.dao.bulletinboard;

import java.util.List;

public class Entry <T> {
    private Integer index;
    private List<T> values;

    public Entry(Integer index, List<T> values) {
        this.index = index;
        this.values = values;
    }

    public Integer getIndex() {
        return index;
    }

    public List<T> getValues() {
        return values;
    }

    public T getValue(int i) {
        return values.get(i);
    }

    public int size() {
        return values.size();
    }
}
