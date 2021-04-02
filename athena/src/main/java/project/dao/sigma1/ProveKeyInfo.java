package project.dao.sigma1;

import java.math.BigInteger;
import java.util.ArrayList;

public class ProveKeyInfo {
    private final ArrayList<BigInteger> y1_yk;
    private final ArrayList<CoinFlipInfo> coinFlipInfo_pairs;
    private final ArrayList<BigInteger> s1_sk;
    private final BigInteger zeta;

    public ProveKeyInfo(ArrayList<BigInteger> y1_yk, ArrayList<CoinFlipInfo> coinFlipInfo_pairs, ArrayList<BigInteger> s1_sk, BigInteger zeta) {

        this.y1_yk = y1_yk;
        this.coinFlipInfo_pairs = coinFlipInfo_pairs;
        this.s1_sk = s1_sk;
        this.zeta = zeta;
    }


    public ArrayList<CoinFlipInfo> getCoinFlipInfoPairs() {
        return coinFlipInfo_pairs;
    }

    public ArrayList<BigInteger> getY1_Yk() {
        return y1_yk;
    }

    public ArrayList<BigInteger> getS1_Sk() {
        return s1_sk;
    }

    public BigInteger getZeta() {
        return zeta;
    }
}
