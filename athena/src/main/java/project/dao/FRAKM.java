package project.dao;

import java.math.BigInteger;

public class FRAKM {
    private BigInteger start;
    private BigInteger end;

    public FRAKM(BigInteger start, BigInteger end) {
        this.start = start;
        this.end = end;
    }
    
    public boolean isInRange(BigInteger value){
        if (value.compareTo(this.start) < 0){
            // value smaller then start value=100 < start=101 
            return false;
        }else if (value.compareTo(this.end) > 0) {
            return false;
        }    
        return true;
    }
}
