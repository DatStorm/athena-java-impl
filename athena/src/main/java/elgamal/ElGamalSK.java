package elgamal;

import java.math.BigInteger;

public class ElGamalSK {
    public final BigInteger sk;
    public final ElGamalPK pk;
    
    public ElGamalSK(Group group, BigInteger sk) {
        this.sk = sk;
        
        BigInteger h = group.g.modPow(sk, group.p); // h=g^sk
        this.pk = new ElGamalPK(group, h);
    }
    
    public BigInteger toBigInteger() {
        return sk;
    }

    public ElGamalPK getPK() {
        return this.pk;
    }

}
