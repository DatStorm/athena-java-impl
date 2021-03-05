package project.sigma.bulletproof;

import com.google.common.collect.Streams;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;

public class PedersenCommitment {


    // Pedersen's commitment g^m * h^r of message m using randomness r. The order denotes the order of the group.
    public static BigInteger commit(BigInteger g, BigInteger h, BigInteger m, BigInteger r, BigInteger order){
        return  g.modPow(m,order).multiply(h.modPow(r,order));
    }


//     // compute a^b for vectors a and b
     private static List<BigInteger> generateListExponentVectors(List<BigInteger> list_a, List<BigInteger> list_b, BigInteger order) {
         return Streams.zip(list_a.stream(), list_b.stream(), (bigInt_a, bigInt_b) -> bigInt_a.modPow(bigInt_b, order)).collect(Collectors.toList());
     }

    // Pedersen's vector commitment h^x gs^ms * hs^rs of message ms using randomness rs. The order denotes the order of the group.
    public static BigInteger commitVector(BigInteger h, BigInteger x, List<BigInteger> gs, List<BigInteger> ms, List<BigInteger> hs, List<BigInteger> rs, BigInteger order){
        List<BigInteger> list_a_exp = generateListExponentVectors(gs,ms,order);
        List<BigInteger> list_b_exp = generateListExponentVectors(hs,rs,order);

        BigInteger temp = Streams.zip(list_a_exp.stream(),list_b_exp.stream(), (e1, e2) -> e1.multiply(e2).mod(order)).reduce(BigInteger.ZERO, BigInteger::add).mod(order);
        return h.modPow(x,order).multiply(temp).mod(order);
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
