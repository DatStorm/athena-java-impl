package project.sigma;

import com.google.common.primitives.UnsignedInts;
import project.UTIL;
import project.dao.bulletproof.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import static project.UTIL.getRandomElement;

public class Bulletproof {

    // Note that when proving range of neg priv cred -d we use range of Z_q = [0,q-1] = [0,2^{10}-1] => n=10
    // Note that when proving range of vote v we use range of [0,nc-1] = [0,2^{log_2(nc)}-1] => n= log_2(nc)
    public static BulletproofProof prooveStatement(BulletproofStatement statement, BulletproofSecret secret) {
        BigInteger m = secret.m;
        BigInteger gamma = secret.gamma;
        BigInteger V = statement.V;
        int n = statement.n;

        BigInteger p = statement.pk.group.p;
        BigInteger q = statement.pk.group.q;
        BigInteger g = statement.pk.group.g;
        BigInteger h = statement.pk.h;

        Random random = new SecureRandom();

        //Extract bit representations from v
        List<BigInteger> a_L = extractBits(V);

        // a_r = a_l - 1 mod q
        List<BigInteger> a_R = a_L.stream()
                .map(big -> big.subtract(BigInteger.ONE).mod(q))
                .collect(Collectors.toList());

        BigInteger alpha = getRandomElement(q, random);

        BigInteger g_a_L = UTIL.modPowSum(g, a_L, p);
        BigInteger h_a_R = UTIL.modPowSum(h, a_R, p);
        BigInteger A = h.modPow(alpha, p).multiply(g_a_L).mod(p).multiply(h_a_R).mod(p); // in G, i.e. subgroup of Z_p^*.

        List<BigInteger> s_L = UTIL.getRandomElements(q, n, random);
        List<BigInteger> s_R = UTIL.getRandomElements(q, n, random);

        BigInteger rho = getRandomElement(q, random);
        BigInteger g_sl = UTIL.modPowSum(g, s_L, p);
        BigInteger h_sr = UTIL.modPowSum(h, s_R, p);
        BigInteger S = h.modPow(rho, p).multiply(g_sl).mod(p).multiply(h_sr).mod(p);


        // Construct challenges y and z. Must be element from group G, i.e. subgroup of Z_p^*.
        Random hashRandom = new Random(hash(A, S));
        BigInteger y = g.modPow(getRandomElement(q, hashRandom), p);
        BigInteger z = g.modPow(getRandomElement(q, hashRandom), p);

        // in Z_q
        BigInteger tau_1 = UTIL.getRandomElement(q, random);
        BigInteger tau_2 = UTIL.getRandomElement(q, random);

        // in Z_q
        BigInteger t1 = UTIL.getRandomElement(q, random);
        BigInteger t2 = UTIL.getRandomElement(q, random);

        // in G, i.e. subgroup of Z_p^*
        BigInteger T_1 = g.modPow(t1,p).multiply(h.modPow(tau_1, p)).mod(p);
        BigInteger T_2 = g.modPow(t2,p).multiply(h.modPow(tau_2, p)).mod(p);


        // Construct challenge x. Must be element from group G, i.e. subgroup of Z_p^*.
        Random hashRandom2 = new Random(hash(A, S, T_1, T_2));
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

        BigInteger t_hat = UTIL.dotProduct(l_vector,r_vector); // <- MARK ;)

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
                .setTau_x(tau_x)
                .setT_hat(t_hat)
                .setMu(mu)
                .setL_vector(l_vector)
                .setR_vector(r_vector)
                .build();
    }

    private static long hash(BigInteger ... args) {
        throw new UnsupportedOperationException();
    }

    public static boolean verifyStatement(BulletproofStatement statement, BulletproofProof proof) {
        // Get the publicly known info
        int n = statement.n;
        BigInteger V = statement.V;
        BigInteger p = statement.pk.group.p;
        BigInteger q = statement.pk.group.q;
        BigInteger g = statement.pk.group.g;
        BigInteger h = statement.pk.group.h;

        // Get the proof info
        BigInteger A = proof.a;
        BigInteger S = proof.s;
        BigInteger y = proof.y;
        BigInteger z = proof.z;
        BigInteger tau_x = proof.tau_x;
        BigInteger mu = proof.mu;
        BigInteger t_hat = proof.t_hat;
        List<BigInteger> l_vector = proof.l_vector;
        List<BigInteger> r_vector = proof.r_vector;


        // First check line (64-65)
        List<BigInteger> h_prime = new ArrayList<>();
        for (int i = 0; i<n; i++){
            BigInteger y_i_1 = y.pow(- i + 1);
            BigInteger hi_prime = h.modPow(y_i_1, p);
            h_prime.add(hi_prime);
        }

        // h^tau_x
        BigInteger h_tau_x = h.pow(tau_x); // FIXME: modPow

        // g^{t_hat} h^{tau_x}
        BigInteger g_t_hat_mult_h_tau_x = g.pow(t_hat).mult(h_tau_x); // FIXME: modPow

        // \delta(y, z) = (z - z^{2}) * [1^{n}, y^{n}] - z^{3} * [1^{n},2^{n}]
        BigInteger delta_yz = delta(y,z,n);

        // g^\delta(y,z)
        BigInteger g_delta_yz = g.pow(delta_yz); // FIXME: modPow
        BigInteger V_z2_g_ = V.pow(z.pow(2)).multiply(g_delta_yz).multiply(T_1_x).multiply(T_2_x_squared); // FIXME: modPow

        boolean check1 = g_t_hat_mult_h_tau_x.compareTo(V_z2_g_) == 0;
        if(!check1){
            return false;
        }


        // Second check equation (66-67)
        // A * S^x * g^{-z} * (h^prime)^{z * y^n +z^2 * 2^n}
        BigInteger P = BigInteger.ONE; //TODO: finish the check

        // h^µ * g^l * (h^prime)^r
        BigInteger hmu_mult_gl_vector_mult_hprimer = BigInteger.ONE; //TODO: finish the check

        boolean check2 = P.mod(p).compareTo(hmu_mult_gl_vector_mult_hprimer) == 0; // FIXME: mod p right?
        if(!check2){
            return false;
        }


        // Third check line 68
        BigInteger innerProd_l_and_r = UTIL.dotProduct(l_vector, r_vector);

        //t_hat == \langle l, r \rangle
        boolean check3 = t_hat.compareTo(innerProd_l_and_r.mod(q)) == 0; // FIXME: mod q right?
        if(!check3){
            return false;
        }

        return true;
    }

    private static List<BigInteger> delta(BigInteger y,BigInteger z, int n) {

        List<BigInteger> _1_vector_n = generateList(1,n,p);
        List<BigInteger> _2_vector_n = generateList(2,n,p);
        List<BigInteger> y_vector_n = generateList(y,n,p);
        BigInteger innerProd_1n_yn = UTIL.dotProduct(_1_vector_n,y_vector_n);


        BigInteger innerProd_1n_2n = UTIL.dotProduct(_1_vector_n,_2_vector_n);
        BigInteger z_3_mult_innerProd_1n_2n = z.pow(3).multiply(innerProd_1n_2n);


        BigInteger z_zSquared = z.subtract(z.pow(2));
        BigInteger value = z_zSquared.multiply(innerProd_1n_yn).subtract(z_3_mult_innerProd_1n_2n);

        return value;
    }

    private static List<BigInteger> generateList(int val, int repitions, BigInteger p){
        // TODO: Should work right now
        // k_vector^n = [k^0, k^1, k^2,..., k^{n-1} ]
        List<BigInteger> vector =  new ArrayList<>();

        for (int i = 0; i < repitions; i++){
            vector.add(BigInteger.valueOf(val).pow(i).mod(p)); // mod q??
        }

        return vector;
    }


    private static List<BigInteger> extractBits(BigInteger v) {
        throw new UnsupportedOperationException();
    }
}
