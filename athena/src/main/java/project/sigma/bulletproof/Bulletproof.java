package project.sigma.bulletproof;

import com.google.common.collect.Streams;
import com.google.common.primitives.Bytes;
import project.UTIL;
import project.dao.bulletproof.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

import static project.UTIL.getRandomElement;

public class Bulletproof {

    private MessageDigest hashH;

    public Bulletproof(MessageDigest hash) {
        hashH = hash;
    }


    // Note that when proving range of neg priv cred -d we use range of Z_q = [0,q-1] = [0,2^{10}-1] => n=10
    // Note that when proving range of vote v we use range of [0,nc-1] = [0,2^{log_2(nc)}-1] => n= log_2(nc)
    public BulletproofProof proveStatement(BulletproofStatement statement, BulletproofSecret secret) {
        BigInteger m = secret.m;
        BigInteger gamma = secret.gamma;
        BigInteger V = statement.V;
        int n = statement.n;

        BigInteger p = statement.pk.getGroup().p;
        BigInteger q = statement.pk.getGroup().q;
        BigInteger g = statement.pk.getGroup().g;
        BigInteger h = statement.pk.getH();

        Random random = new SecureRandom();

        /* ********
         * Step 1: Create a_L, a_R, A, S
         *********/

        //Extract bit representations from m
        List<BigInteger> a_L = extractBits(m, n);

        // a_r = a_l - 1 mod q
        List<BigInteger> a_R = a_L.stream()
                .map(big -> big.subtract(BigInteger.ONE).mod(q))
                .collect(Collectors.toList());


        BigInteger alpha = getRandomElement(q, random);
        BigInteger A = computeAorS(alpha, g, p, q, h, random, a_L, a_R);

        List<BigInteger> s_L = UTIL.getRandomElements(q, n, random);
        List<BigInteger> s_R = UTIL.getRandomElements(q, n, random);
        BigInteger rho = getRandomElement(q, random);
        BigInteger S = computeAorS(rho, g, p, q, h, random, s_L, s_R);


        /* ********
         * Step 2: Send A,S => Hash(A,S)
         *********/
        // Construct challenges y and z. Must be element from group G, i.e. subgroup of Z_p^*.
        Random hashRandom = new Random(hash(A, S));



        /* ********
         * Step 3: Generate y,z \in_R G
         *********/
        BigInteger y = g.modPow(getRandomElement(q, hashRandom), p);
        BigInteger z = g.modPow(getRandomElement(q, hashRandom), p);



        /* ********
         * Step 4: Generate tau1, tau2, t1, t2, T1, T2
         *********/
        // in Z_q
        BigInteger tau_1 = UTIL.getRandomElement(q, random);
        BigInteger tau_2 = UTIL.getRandomElement(q, random);

        // in Z_q
        BigInteger t1 = UTIL.getRandomElement(q, random);
        BigInteger t2 = UTIL.getRandomElement(q, random);


        // in G, i.e. subgroup of Z_p^*
        BigInteger T_1 = g.modPow(t1, p).multiply(h.modPow(tau_1, p)).mod(p);
        BigInteger T_2 = g.modPow(t2, p).multiply(h.modPow(tau_2, p)).mod(p);


        /* ********
         * Step 5: Send T1,T2 => Hash(A,S,T1,T2) [all communication so far]
         *********/
        // Construct challenge x. Must be element from group G, i.e. subgroup of Z_p^*.
        Random hashRandom2 = new Random(hash(A, S, T_1, T_2)); // FIXME: would the prover not be able to cheat? Does the random not return two different values for same input?
        BigInteger x = g.modPow(getRandomElement(q, hashRandom2), p);


        List<BigInteger> l_vector = new ArrayList<>(n); // l = a_L - z * 1^n + s_L * x
        for (int i = 0; i < n; i++) {
            BigInteger a_L_i = a_L.get(i);
            BigInteger s_L_i = s_L.get(i);
            BigInteger a = a_L_i.subtract(z).add(s_L_i.multiply(x)).mod(p);
            l_vector.add(a);
        }

        List<BigInteger> r_vector = new ArrayList<>(n); // r = y^n \circ (a_R + z * 1^n + s_R * x) + z^2 * 2^n
        for (int i = 0; i < n; i++) {
            BigInteger a_R_i = a_L.get(i);
            BigInteger s_R_i = s_L.get(i);
            BigInteger a = a_R_i.add(z).add(s_R_i.multiply(x)).add(z.pow(2).multiply(BigInteger.TWO.pow(n))).mod(p);
            r_vector.add(a);
        }

        BigInteger t_hat = UTIL.dotProduct(l_vector, r_vector);

        // tau_x = tau_2 * x^2 + tau_1 * x + z^2 * gamma mod q
        BigInteger x_squared = x.pow(2);
        BigInteger tau_1_mult_x = tau_1.multiply(x).mod(q);
        BigInteger z_squared_mult_gamma = z.pow(2).multiply(gamma).mod(q);
        BigInteger tau_x = tau_2.multiply(x_squared).mod(q).add(tau_1_mult_x).mod(q).add(z_squared_mult_gamma).mod(q);

        // mu = alpha + rho * x mod q
        BigInteger rho_mult_x = rho.multiply(x).mod(q);
        BigInteger mu = alpha.add(rho_mult_x).mod(q);

        //Build proof
        return new BulletproofProof.Builder()
                .setAS(A, S)
                .setYZ(y, z)
                .setT1_T2(T_1, T_2)
                .setX(x)
                .setTau_x(tau_x)
                .setT_hat(t_hat)
                .setMu(mu)
                .setL_vector(l_vector)
                .setR_vector(r_vector)
                .build();
    }


    public boolean verifyStatement(BulletproofStatement statement, BulletproofProof proof) {
        // Get the publicly known info
        int n = statement.n;
        BigInteger V = statement.V;
        BigInteger p = statement.pk.getGroup().p;
        BigInteger q = statement.pk.getGroup().q;
        BigInteger g = statement.pk.getGroup().g;
        BigInteger h = statement.pk.getH();

        // Get the proof info
        BigInteger A = proof.a;
        BigInteger S = proof.s;
        BigInteger y = proof.y;
        BigInteger z = proof.z;
        BigInteger T_1 = proof.T_1;
        BigInteger T_2 = proof.T_2;
        BigInteger x = proof.x;
        BigInteger tau_x = proof.tau_x;
        BigInteger mu = proof.mu;
        BigInteger t_hat = proof.t_hat;
        List<BigInteger> l_vector = proof.l_vector;
        List<BigInteger> r_vector = proof.r_vector;


        // First check line (64-65)
        List<BigInteger> h_prime = new ArrayList<>();
        for (int i = 0; i < n; i++) {
//            BigInteger _y_i_1 = y.pow(-i + 1); // TODO: IS BELOW CORRECT
            BigInteger val = BigInteger.valueOf(-i + 1);
            BigInteger y_i_1 = y.modPow(val, p);
            BigInteger hi_prime = h.modPow(y_i_1, p);
            h_prime.add(hi_prime);
        }

        // h^tau_x
        BigInteger h_tau_x = h.modPow(tau_x, p);

        // g^{t_hat} h^{tau_x}
        BigInteger g_t_hat_mult_h_tau_x = g.modPow(t_hat, p).multiply(h_tau_x).mod(p);

        // \delta(y, z) = (z - z^{2}) * [1^{n}, y^{n}] - z^{3} * [1^{n},2^{n}]
        BigInteger delta_yz = delta(y, z, n, p);

        // g^\delta(y,z)
        BigInteger g_delta_yz = g.modPow(delta_yz, p);
        BigInteger T_1_x = T_1.modPow(x, p);
        BigInteger T_2_x_squared = T_1.modPow(x.pow(2), p);
        BigInteger V_z2_g_ = V.modPow(z.pow(2), p).multiply(g_delta_yz).mod(p).multiply(T_1_x).mod(p).multiply(T_2_x_squared).mod(p);

        boolean check1 = g_t_hat_mult_h_tau_x.compareTo(V_z2_g_) == 0;
        if (!check1) {
            System.err.println("Bulletproof.verifyStatement g^t_hat * h^tau_x != V^{z^2} * g^ delta(y,z) * T1^x T2^{x^2}");
            System.err.println("Bulletproof.verifyStatement g^t_hat * h^tau_x: \t\t\t\t\t\t\t" + g_t_hat_mult_h_tau_x);
            System.err.println("Bulletproof.verifyStatement V^{z^2} * g^ delta(y,z) * T1^x T2^{x^2}: \t" + V_z2_g_);
            return false;
        }


        // Second check equation (66-67), see line 44 and 47 for the provers role in this
        List<BigInteger> g_vector = generateConstList(g, n); // FIXME: It this correct?
        List<BigInteger> z_vector = generateConstList(z.negate(), n); // FIXMe: TODO: This must be a vector according to completeness.

        // A * S
        BigInteger A_mult_S = A.multiply(S).mod(p);

        // g^{-z} * (h^prime)^{z * y^n +z^2 * 2^n}
        List<BigInteger> exponentTempP1 = generateListMultWithBigInt(generateList(y, n, q), z, q);
        List<BigInteger> exponentTempP2 = generateListMultWithBigInt(generateList(BigInteger.TWO, n, q), z.pow(2), q);
        List<BigInteger> exponentTemp = generateListAddVectors(exponentTempP1, exponentTempP1, q);

        // A * S^x * g^{-z} * (h^prime)^{z * y^n +z^2 * 2^n}
        BigInteger commitVectorP_left = PedersenCommitment.commitVector(A_mult_S, x, g_vector, z_vector, h_prime, exponentTemp, p); // FIXME: maybe error (A*S)^x vs A*S^x

        // A * S^x * g^{-z} * (h^prime)^{z * y^n +z^2 * 2^n}
        BigInteger P = null; //FIXME: How to compute this? Seems like you need to compute inner product

        // h^µ * g^l * (h^prime)^r
        List<BigInteger> g_l = generateListExponentVectors(g_vector, l_vector, p);
        List<BigInteger> hprime_r = generateListExponentVectors(h_prime, r_vector, p);
        BigInteger g_l_mult_hprime_r = null; //FIXME: How to compute this? Seems like you need to compute inner product
        BigInteger hmu_mult_gl_vector_mult_hprimer = h.modPow(mu, p).multiply(g_l_mult_hprime_r).mod(p);

        boolean check2 = P.mod(p).compareTo(hmu_mult_gl_vector_mult_hprimer) == 0; // FIXME: mod p right?
        if (!check2) {
            System.err.println("Bulletproof.verifyStatement P != ...");
            return false;
        }


        // Third check line 68
        BigInteger innerProd_l_and_r = UTIL.dotProduct(l_vector, r_vector);

        //t_hat == \langle l, r \rangle
        boolean check3 = t_hat.compareTo(innerProd_l_and_r.mod(q)) == 0; // FIXME: mod q right?
        if (!check3) {
            System.err.println("Bulletproof.verifyStatement t_hat != 〈l,r〉");
            return false;
        }

        return true;
    }

    private BigInteger delta(BigInteger y, BigInteger z, int n, BigInteger p) {

        List<BigInteger> _1_vector_n = generateList(BigInteger.valueOf(1), n, p);
        List<BigInteger> _2_vector_n = generateList(BigInteger.valueOf(2), n, p);
        List<BigInteger> y_vector_n = generateList(y, n, p);
        BigInteger innerProd_1n_yn = UTIL.dotProduct(_1_vector_n, y_vector_n);

        BigInteger innerProd_1n_2n = UTIL.dotProduct(_1_vector_n, _2_vector_n);
        BigInteger z_3_mult_innerProd_1n_2n = z.pow(3).multiply(innerProd_1n_2n);

        BigInteger z_zSquared = z.subtract(z.pow(2));

        // TODO: Should be in Z_q
        BigInteger value = z_zSquared.multiply(innerProd_1n_yn).subtract(z_3_mult_innerProd_1n_2n);

        return value;
    }

    private List<BigInteger> generateConstList(BigInteger val, int repitions) {
        return Collections.nCopies(repitions, val);
    }

    // k_vector^n = [k^0, k^1, k^2,..., k^{n-1}]
    private List<BigInteger> generateList(BigInteger val, int repitions, BigInteger order) {
        // TODO: Should work right now
        List<BigInteger> vector = new ArrayList<>();

        for (int i = 0; i < repitions; i++) {
            vector.add(val.pow(i).mod(order));
        }

        return vector;
    }

    /******************************************************************************************
     ********************************  HYYGGGGEEEE MARK ***************************************
     ******************************************************************************************/
    private BigInteger computeAorS(BigInteger alpha_rho, BigInteger g, BigInteger p, BigInteger q, BigInteger h, Random random, List<BigInteger> a_L_sL, List<BigInteger> a_R_s_R) {

        // OLD COMPUTE A
//        BigInteger alpha = getRandomElement(q, random);
//        BigInteger g_a_L = UTIL.modPowSum(g, a_L, p); // FIXME: is this the way to do it? If so how to you know? How to you know the base is fixed?
//        BigInteger h_a_R = UTIL.modPowSum(h, a_R, p); // FIXME: is this the way to do it? If so how to you know? How to you know the base is fixed?
//        BigInteger A = h.modPow(alpha, p).multiply(g_a_L).mod(p).multiply(h_a_R).mod(p); // in G, i.e. subgroup of Z_p^*.

        // OLD COMPUTE S
//        List<BigInteger> s_L = UTIL.getRandomElements(q, n, random);
//        List<BigInteger> s_R = UTIL.getRandomElements(q, n, random);
//
//        BigInteger rho = getRandomElement(q, random);
//        BigInteger g_sl = UTIL.modPowSum(g, s_L, p); // FIXME: is this the way to do it? If so how to you know? How to you know the base is fixed?
//        BigInteger h_sr = UTIL.modPowSum(h, s_R, p); // FIXME: is this the way to do it? If so how to you know? How to you know the base is fixed?
//        BigInteger S = h.modPow(rho, p).multiply(g_sl).mod(p).multiply(h_sr).mod(p);


        // TODO: KALD SKIPPER FUNCTION!!!
        BigInteger g_a_L_g_sl = UTIL.modPowSum(g, a_L_sL, p); // FIXME: is this the way to do it? If so how to you know? How to you know the base is fixed?
        BigInteger h_a_R_h_sr = UTIL.modPowSum(h, a_R_s_R, p); // FIXME: is this the way to do it? If so how to you know? How to you know the base is fixed?
        BigInteger A_or_S = h.modPow(alpha_rho, p).multiply(g_a_L_g_sl).mod(p).multiply(h_a_R_h_sr).mod(p); // in G, i.e. subgroup of Z_p^*.

        return A_or_S;
    }


    private long hash(BigInteger... values) {
        byte[] concatenated = new byte[]{};
        for (BigInteger bigInt : values) {
            concatenated = Bytes.concat(concatenated, bigInt.toByteArray());
        }
        byte[] hashed = this.hashH.digest(concatenated);

        // create positive long value.
        return new BigInteger(1, hashed).longValue();
    }


    // compute g^x for vector g and biginteger x
    private List<BigInteger> generateExponentList(List<BigInteger> list, BigInteger val, BigInteger order) {
        return list.stream().map(element -> element.modPow(val, order)).collect(Collectors.toList());
    }

    // compute x*g for vector g and biginteger x
    private List<BigInteger> generateListMultWithBigInt(List<BigInteger> list, BigInteger val, BigInteger order) {
        return list.stream().map(element -> val.multiply(element).mod(order)).collect(Collectors.toList());
    }

    // compute a+b for vectors a and b
    private List<BigInteger> generateListAddVectors(List<BigInteger> list_a, List<BigInteger> list_b, BigInteger order) {
        return Streams.zip(list_a.stream(), list_b.stream(), (bigInt_a, bigInt_b) -> bigInt_a.add(bigInt_b).mod(order)).collect(Collectors.toList());
    }


    // Returns a list of the bits
    private List<BigInteger> extractBits(BigInteger m, int n) {
        String bitsString = m.toString(2);

        //Extract bits TODO: Test me
        BitSet bits = new BitSet(n);
        int i = 0;
        for (int j = bitsString.length() - 1; j >= 0; j++) {
            boolean bit = bitsString.charAt(j) == '1';
            bits.set(i, bit);
            i++;
        }

        //Cast to List<BigInteger>
        return bits.stream()
                .mapToObj(BigInteger::valueOf)
                .collect(Collectors.toList());


        /*

        System.out.println("--> M: " + m);
        System.out.println("--> M: " + m.toString(2)); // get each bit...
        System.out.println("--> n: " + n);


        // [2^0, 2^1, 2^2,..., 2^{n-1}] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]
        List<BigInteger> _2_vector_n = generateList(BigInteger.valueOf(2), n, p);
        System.out.println("--> 2 list: " + _2_vector_n);


        // TODO: HACKY AS FUCK!!!!!!!!
        // a_L = [0,0,1,0,1,1,1,0,0,0,0], |a_L| = n
//        List<BigInteger> a_L = new ArrayList<>(n);
        List<BigInteger> a_L = Stream.of(1, 0, 1, 0, 0, 0, 0, 0, 0, 0).map(BigInteger::valueOf).collect(Collectors.toList());

        if ((n % 2) != 0) {
            System.out.println("n odd does not work at the moment...");
        }

//        a_L.addAll(Collections.nCopies(n/2, BigInteger.ONE));
//        a_L.addAll(Collections.nCopies(n/2, BigInteger.ZERO));
//
//        Collections.shuffle(a_L);

        System.out.println("--> a_L list: " + a_L);


        while (!UTIL.dotProduct(a_L, _2_vector_n).equals(m)) {
            Collections.shuffle(a_L);
        }


        if (UTIL.dotProduct(a_L, _2_vector_n).equals(m)) {
            System.out.println("ALLL GOOD!!");
        }


        return a_L;
     */
    }

}
