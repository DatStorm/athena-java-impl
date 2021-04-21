package cs.au.athena.elgamal;

import java.math.BigInteger;

// Creating a 1-1 mapping from Z_q to G, where G is a subgroup of Z_p^* for primes q, p=2q+1
public class GroupTheory {
    public static BigInteger fromZqToG(BigInteger element, Group group){
        BigInteger p = group.p;
        BigInteger y = element.add(BigInteger.ONE);
        BigInteger tmp_y = y.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.TWO),p);
        if(tmp_y.equals(BigInteger.ONE)){
            return y;
        }
        return y.negate().mod(p).add(p).mod(p);
    }

    public static BigInteger fromGToZq(BigInteger element, Group group){
        BigInteger q = group.q;
        BigInteger p = group.p;
        BigInteger y;

        // element <= q
        if (element.compareTo(q) <= 0) {
            y = element;
        } else {
            y = element.negate().mod(p).add(p).mod(p);
        }

        return y.subtract(BigInteger.ONE);
    }


}
