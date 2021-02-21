package project.mixnet;

import com.google.common.primitives.Bytes;
import project.CONSTANTS;
import project.UTIL;
import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixnetProof;
import project.dao.mixnet.MixnetStatement;
import project.elgamal.CipherText;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.factory.Factory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

public class Mixnet {
//    private final int n = CONSTANTS.MIXNET_N;
    private final int n = 2;
    private final MessageDigest hashH;
    private final ElGamal elgamal;
    private final Random random;
    private final ElGamalPK pk;


    public Mixnet(Factory factory) {
        this.hashH = factory.getHash();
        this.elgamal = factory.getElgamal();
        this.random = factory.getRandom();
        this.pk = factory.getPK();

    }


    public MixnetProof proveMix(MixnetStatement stmt) {

        List<MixBallot> listOfB = stmt.getB();
        int ell = listOfB.size();


        Map<Integer, List<CipherText>> mapOfBj = new HashMap<>(n);
        for (int i = 1; i <= n; i++) {

            /* *******************
             * Step 1
             *********************/
            List<CipherText> listOfBj_prime = step1(listOfB, ell);


            /* *******************
             * Step 2
             *********************/
            List<CipherText> Bcal_prime = step2(listOfBj_prime);


            /* *******************
             * Step 3
             *********************/
            mapOfBj.put(i, Bcal_prime);
        }


        /* *******************
         * Step 4
         *********************/
        List<Boolean> listOfCs = hash(mapOfBj);
        List<BigInteger> reencDataBj;
        List<Integer> permDataBj;
        List<BigInteger> listOfReencDataBj = new ArrayList<>();
        List<List<Integer>> listOfPermDataBj = new ArrayList<>();

        for (Boolean challengej : listOfCs) {
            if (challengej) {// challenge c = 1
                // composed randomness s'_{i,j}, composition of randomness used to create Bj and B'
                reencDataBj = 

                // composed permutation pi'_j, composition of permutation used to create Bj and B'
                permDataBj =
            } else { // challenge c = 0
                // randomness s_{i,j} used to create Bj
                reencDataBj =

                // permutation pi_j used to create Bj
                permDataBj =
            }

                //Add reenc data
                listOfReencDataBj.add(reencDataBj);

                //Add permutation data
                listOfPermDataBj.add(permDataBj);
        }
        // do nothing with the list for now....

        List<CipherText> listOfBj_prime = null; // FIXME: ADD??

        return new MixnetProof(listOfBj_prime, mapOfBj, listOfReencDataBj, listOfPermDataBj);
    }

    private List<CipherText> step2(List<CipherText> listOfBj_prime) {
        // TODO: MARK!!!!!
        /*
        Instead of randomly permuting the elements of the new
        ballot set, the re-encrypted ballots can simply be sorted
        numerically, alphabetically, or lexicographically
        to obscure the association between the original encrypted ballots
        and the re-encrypted ballots
         */
        List<Integer> listOfPermutationsPI = new ArrayList<>(Arrays.asList(2, 1, 0)); // TODO: FAKE!!
//        List<Integer> listOfPermutationsPI = listOfBi_prime.sort(Comparator.comparing(CipherText::sort)); // TODO: FAKE!!


        List<CipherText> Bcal_prime = permute(listOfBj_prime, listOfPermutationsPI);
        return Bcal_prime;
    }


    private List<CipherText> step1(List<MixBallot> listOfB, int ell) {
        List<CipherText> listOfBi_prime = new ArrayList<>(ell);
        for (int i = 1; i <= ell; i++) {

            // bi = {c1=Enc_pk(1)=(g^r,1h^r),c2=Enc_pk(v)}
            MixBallot bi = listOfB.get(i - 1); // TODO: i starts at 1.....

            BigInteger fromInclusive = BigInteger.valueOf(1);
            BigInteger toExclusive = BigInteger.valueOf(3);
            BigInteger si = UTIL.getRandomElement(fromInclusive, toExclusive, this.random);
            BigInteger e = BigInteger.valueOf(1); // TODO: fix si
            CipherText c = elgamal.encrypt(e, pk, si.longValueExact()); // c =  Enc_pk(e; si)
            // bi.c0.c1 * c.c1
            // bi.c0.c2 * c.c2
            // bi.c2 * c.c2

            CipherText bi_prime = bi.multiply(c); // bi^\prime = bi \cdot c
            listOfBi_prime.add(bi_prime);
        }
        return listOfBi_prime;
    }

    private List<Boolean> hash(Map<Integer, List<CipherText>> mapOfBj) {

        byte[] concatenated = new byte[]{};
        for (List<CipherText> Bcal_j : mapOfBj.values()) {

            for (CipherText c : Bcal_j) {
                BigInteger c1 = c.c1;
                BigInteger c2 = c.c2;
                concatenated =  Bytes.concat(concatenated,c1.toByteArray(),c2.toByteArray());
            }
        }
        
        byte[] hashed = this.hashH.digest(concatenated);
        
        // create list of C
        List<Boolean> listOfC = ByteConverter.valueOf(hashed, hashed.length);

        // TODO: HACKY ONLY TAKES THE FIRST n......
        List<Boolean> firstNElementsOfC = listOfC.stream().limit(n).collect(Collectors.toList());

        assert firstNElementsOfC.size() == n : "listOfC.size()="+ listOfC.size()+  " != n=" + n;
        return firstNElementsOfC;
    }


    public ArrayList<CipherText> permute(List<CipherText> ciphertexts, List<Integer> pi) {
        //pi [0,2,3,1,4].

        ArrayList<CipherText> ciphertextsPermuted = new ArrayList<>();
        for (int i = 0; i < pi.size(); i++) {
            ciphertextsPermuted.add(ciphertexts.get(pi.get(i)));
        }
        return ciphertextsPermuted;
    }


    public boolean verify(MixnetProof proof) {

        Map<Integer, List<CipherText>> mapOfBj = proof.getMapOfBj();

        List<Boolean> listOfCis = hash(mapOfBj);

        for (Map.Entry<Integer, List<CipherText>> entry : mapOfBj.entrySet()) {
            Integer i = entry.getKey();
            Boolean ci = listOfCis.get(i);
            if (ci) {
                /* *******************
                 * Step 6 (c_i == 1)
                 * Bi =?= B_prime
                 *********************/


                return false;
            } else {
                /* *******************
                 * Step 5 (c_i == 0)
                 *********************/

                return true;

            }

        }


        return true;
    }

}
