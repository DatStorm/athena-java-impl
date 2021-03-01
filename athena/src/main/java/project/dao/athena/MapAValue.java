package project.dao.athena;

import project.elgamal.CipherText;

public class MapAValue {
    private final int cnt;
    private final CipherText cipher1;
    private final CipherText cipher2;

    public MapAValue(int cnt, CipherText cipher1, CipherText cipher2) {
        this.cnt = cnt;
        this.cipher1 = cipher1;
        this.cipher2 = cipher2;
    }

    public int get1() {
        return cnt;
    }
}
