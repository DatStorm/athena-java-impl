package project.sigma.bulletproof;

import com.google.common.collect.Streams;

import java.math.BigInteger;
import java.util.List;

public class PedersenCommitment {


    // Pedersen's commitment g^m * h^r of message m using randomness r.
    // The order denotes the order of the group.
    public static BigInteger commit(
        BigInteger g,
        BigInteger m,
        BigInteger h,
        BigInteger r,
        BigInteger order){

        return  g.modPow(m,order).multiply(h.modPow(r,order)).mod(order);
    }



     // compute a^b for vectors a and b
     private static BigInteger exponentProductSequence(
         List<BigInteger> list_a,
         List<BigInteger> list_b,
         BigInteger order) {

         return Streams.zip(list_a.stream(), list_b.stream(),
            (bigInt_a, bigInt_b) -> bigInt_a.modPow(bigInt_b, order)
         )
         .reduce(BigInteger.ONE, BigInteger::multiply);
     }

    // Pedersen's vector commitment h^x gs^ms * hs^rs of message ms using randomness rs.
    // The order denotes the order of the group.
    public static BigInteger commitVector(
        BigInteger h,
        BigInteger x,
        List<BigInteger> gs,
        List<BigInteger> ms,
        List<BigInteger> hs,
        List<BigInteger> rs,
        BigInteger order){

        //g^a
        BigInteger list_a_exp = exponentProductSequence(gs,ms,order); //gs^ms

        //h^b
        BigInteger list_b_exp = exponentProductSequence(hs,rs,order); //hs^rs

        // h^x * g^a * h^b
        return h.modPow(x,order)
                .multiply(list_a_exp).mod(order)
                .multiply(list_b_exp).mod(order);
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
