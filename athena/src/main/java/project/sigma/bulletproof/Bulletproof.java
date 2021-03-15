package project.sigma.bulletproof;

import com.google.common.collect.Streams;
import com.google.common.primitives.Bytes;
import project.UTIL;
import project.dao.bulletproof.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

import static project.UTIL.getRandomElement;
import static project.UTIL.subtractLists;

public class Bulletproof {
    private MessageDigest hashH;
    private Random random;

    public Bulletproof(MessageDigest hash, Random random) {
        this.hashH = hash;
        this.random = random;
    }


    /**
    * Note that when proving range of neg priv cred -d we use range of Z_q = [0,q-1] = [0,2^{1024}-1] => n=1024 as q is 1024 bits
    * Note that when proving range of vote v we use range of [0,nc-1] = [0,2^{log_2(nc)}-1] => n= log_2(nc)
    **/
    public BulletproofProof proveStatement(BulletproofStatement statement, BulletproofSecret secret) {
        BigInteger m = secret.m;
        BigInteger gamma = secret.gamma;
        BigInteger V = statement.V;
        int n = statement.n;

        BigInteger p = statement.pk.getGroup().p;
        BigInteger q = statement.pk.getGroup().q;
        BigInteger g = statement.pk.getGroup().g;
        BigInteger h = statement.pk.getH();

        List<BigInteger> g_vector = statement.g_vector; // generateConstList(g
        // , n); // FIXME: the g element might need to be different to maintain binding, put in statement
        List<BigInteger> h_vector = statement.h_vector; // generateConstList(h, n); // FIXME: the h element might need to be different to maintain binding, put in statement
        List<BigInteger> _1n_vector = generateList(BigInteger.ONE, n, q);
        List<BigInteger> _2n_vector = generateList(BigInteger.TWO, n, q);


        /* ********
         * Step 1: Create a_L, a_R, A, S
         *********/
        //Extract bit representations from m, s.t. <a_L, 2^n> = m
        List<BigInteger> a_L = extractBits(m, n);
        assert a_L.size() == n : "|" + a_L.toString() + "| != n";

        // a_R = a_L - 1 mod q
        List<BigInteger> a_R = UTIL.subtractLists(a_L, _1n_vector, q);
        assert a_R.size() == n : "|a_L| != n";



        /* ********
         * EQ 37 asserts: <a_L, 2^n> = m , a_L circ a_R = 0^n, a_R = a_L - 1^n
         *********/
        // Equation (37) -> <a_L, 2^n> = m
        assert UTIL.dotProduct(a_L, _2n_vector, q).equals(m) : "EQ 37: dot(a_L, 2^n) = " + UTIL.dotProduct(a_L, _2n_vector, q) + "!= m=" + m;

        // Equation (37) ->  a_L circ a_R = 0^n
        for (BigInteger value : UTIL.hadamardProduct(a_L, a_R, q)) {
            assert value.equals(BigInteger.ZERO) : "EQ 37: hadamard(a_L, a_R)[i] != 0";
        }
        // Equation (37) ->  a_R = a_L - 1^n
        assert Arrays.deepEquals(a_R.toArray(), subtractLists(a_L, _1n_vector, q).toArray()) : "EQ 37: a_R != a_L - 1^n";


        BigInteger alpha = getRandomElement(q, random);
        BigInteger A = PedersenCommitment.commitVector(h, alpha, g_vector, a_L, h_vector, a_R, p);
        List<BigInteger> s_L = UTIL.getRandomElements(q, n, random);
        List<BigInteger> s_R = UTIL.getRandomElements(q, n, random);
        BigInteger rho = getRandomElement(q, random);

        BigInteger S = PedersenCommitment.commitVector(h, rho, g_vector, s_L, h_vector, s_R, p);


        // Step 2: Send A,S => Hash(A,S)
        // Step 3: Generate y,z \in_R Z_q \ 0
        Random hashRandom = new Random(hash(A, S));

        BigInteger y = generateChallenge(q, hashRandom);
        Random hashRandom2 = new Random(hash(A, S, y));
        BigInteger z = generateChallenge(q, hashRandom2);


        /* ********
         * Step 4: Generate tau1, tau2, t1, t2, T1, T2 \in_R Z_q
         *********/
        BigInteger tau_1 = getRandomElement(q, random);
        BigInteger tau_2 = getRandomElement(q, random);



        // Generate y^n
        List<BigInteger> yn_vector = generateList(y, n, q);

        // t1, t2 \in Z_q
        List<BigInteger> compute_ts = compute_t0_t1_t2(n,a_L,a_R,s_L,s_R,q,z, y, yn_vector,_2n_vector );
        BigInteger t0 = compute_ts.get(0);
        BigInteger t1 = compute_ts.get(1);
        BigInteger t2 = compute_ts.get(2);



        // in G, i.e. subgroup of Z_p^*
        BigInteger T_1 = PedersenCommitment.commit(g, t1, h, tau_1, p);
        BigInteger T_2 = PedersenCommitment.commit(g, t2, h, tau_2, p);


        /* ********
         * Step 5: Send T1,T2 => x = Hash(A,S,T1,T2)  [all communication so far]
         *********/
        // Construct challenge x.
        Random hashRandom3 = new Random(hash(A, S, T_1, T_2));
        BigInteger x = generateChallenge(q, hashRandom3);


        // l = a_L - z * 1^n + s_L * x
        List<BigInteger> l_vector = compute_l_vector(n, q, a_L, s_L, z, x);

        // r = (y^n o (aR + z) + 2^n * z^2) + (sR o y^n * x)
        List<BigInteger> r_vector = compute_r_vector(n, q, a_R, s_R, z, x, yn_vector, _2n_vector);

        BigInteger t_hat = UTIL.dotProduct(l_vector, r_vector, q);

        // Equation 61: tau_x = tau_2 * x^2 + tau_1 * x + z^2 * gamma mod q
        BigInteger x_squared = x.pow(2);
        BigInteger tau_1_mult_x = tau_1.multiply(x).mod(q);
        BigInteger z_squared_mult_gamma = z.pow(2).multiply(gamma).mod(q);
        BigInteger tau_x = tau_2.multiply(x_squared).mod(q).add(tau_1_mult_x).mod(q).add(z_squared_mult_gamma).mod(q);

        // mu = alpha + rho * x mod q
        BigInteger rho_mult_x = rho.multiply(x).mod(q);
        BigInteger mu = alpha.add(rho_mult_x).mod(q);



        // Equation (38) -> <a_L, a_R o y^n> = 0
        assert UTIL.dotProduct(a_L, UTIL.hadamardProduct(a_R, yn_vector, q), q).equals(BigInteger.ZERO) : "EQ 38: dot(a_L, a_R circ y^n) != 0";

        // Equation (38) -> <a_L - 1^n - a_R, y^n> = 0
        List<BigInteger> a_L_1n_a_R = UTIL.subtractLists(UTIL.subtractLists(a_L, _1n_vector, q), a_R, q);
        assert UTIL.dotProduct(a_L_1n_a_R, yn_vector, q).equals(BigInteger.ZERO) : "EQ 38:  dot(a_L - 1^n - a_R, y^n) != 0";

        //assert: <l(x), r(x)> =  t0 +  t_1 * X +  t_2 * X2
        BigInteger tx = t0.add(t1.multiply(x)).add(t2.multiply(x.pow(2))).mod(q);
        assert t_hat.equals(tx) : "EQ ??: t_hat=<l(x), r(x)> !=  t0 +  t_1 * X +  t_2 * X2";

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

    private BigInteger generateChallenge(BigInteger q, Random hashedRandom) {
        return getRandomElement(BigInteger.ONE, q, hashedRandom);
    }

    public List<BigInteger> compute_t0_t1_t2(int n, List<BigInteger> a_L, List<BigInteger> a_R, List<BigInteger> s_L, List<BigInteger> s_R, BigInteger q, BigInteger z, BigInteger y, List<BigInteger> yn_vector, List<BigInteger> _2n_vector) {
        BigInteger t0 = BigInteger.ZERO;
        BigInteger t1 = BigInteger.ZERO;
        BigInteger t2 = BigInteger.ZERO;
        for (int i = 0; i < n; i++) {
            BigInteger aLi = a_L.get(i);
            BigInteger aRi = a_R.get(i);
            BigInteger sLi = s_L.get(i);
            BigInteger sRi = s_R.get(i);

            BigInteger tmp = aLi.subtract(z).multiply(sRi).mod(q).add(aRi.add(z).multiply(sLi).mod(q)).mod(q); //(aLi-z)sRi + (aRi+z)sLi
            t1 = t1.add(yn_vector.get(i).multiply(tmp)).mod(q);
            t1 = t1.add(sLi.multiply(z.pow(2)).multiply(_2n_vector.get(i))).mod(q);   // sLi * z^2 * 2^i

            t2 = t2.add(yn_vector.get(i).multiply(sLi).multiply(sRi).mod(q)).mod(q); // y^i * sLi * sRi

            t0 = t0.add(yn_vector.get(i).multiply(aLi.multiply(aRi.add(z)).subtract(z.multiply(aRi)).subtract(z.pow(2))).add( _2n_vector.get(i).multiply(aLi.multiply(z.pow(2)).subtract(z.pow(3)))));
            t0 = t0.mod(q);
        }
        return Arrays.asList(t0,t1,t2);
    }


    public List<BigInteger> compute_r_vector(int n, BigInteger q, List<BigInteger> a_R, List<BigInteger> s_R, BigInteger z, BigInteger x, List<BigInteger> yn_vector, List<BigInteger> twon_vector) {
        List<BigInteger> r_vector = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            BigInteger a_R_i = a_R.get(i);
            BigInteger s_R_i = s_R.get(i);

            // r = y^n \circ (a_R + z * 1^n + s_R * x) + z^2 * 2^n
            BigInteger r;
            r = a_R_i.add(z).add(s_R_i.multiply(x).mod(q)).mod(q);
            r = yn_vector.get(i).multiply(r).mod(q);
            r = r.add(z.pow(2).multiply(twon_vector.get(i)).mod(q)).mod(q);
            r_vector.add(r);
        }
        return r_vector;
    }

    public List<BigInteger> compute_l_vector(int n, BigInteger q, List<BigInteger> a_L, List<BigInteger> s_L, BigInteger z, BigInteger x) {
        List<BigInteger> l_vector = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            BigInteger a_L_i = a_L.get(i);
            BigInteger s_L_i = s_L.get(i);
            BigInteger a = a_L_i.subtract(z).add(s_L_i.multiply(x).mod(q)).mod(q).add(q).mod(q);
            l_vector.add(a);
        }
        return l_vector;
    }


    public boolean verifyStatement(BulletproofStatement statement, BulletproofProof proof) {
        // Get the publicly known info
        int n = statement.n;
        BigInteger V = statement.V;
        BigInteger p = statement.pk.getGroup().p;
        BigInteger q = statement.pk.getGroup().q;
        BigInteger g = statement.pk.getGroup().g;
        BigInteger h = statement.pk.getH();
        List<BigInteger> g_vector = statement.g_vector;
        List<BigInteger> h_vector = statement.h_vector;

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

        List<BigInteger> yn_vector = generateList(y, n, q);

        

        // k^{-n}= (k^{-1})^{n}= [k^0, k^{-1}, k^{-2},..., k^{-n+1}]
        BigInteger y_inv = y.modInverse(q);
        List<BigInteger> y_inv_n_vector = generateList(y_inv, n, q);


        // First check line (64-65)
        List<BigInteger> h_prime = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger y_i_1 = y_inv_n_vector.get(i);
            BigInteger hi_prime = h_vector.get(i).modPow(y_i_1, p);
            h_prime.add(hi_prime);
        }
        assert Arrays.deepEquals(UTIL.generateListExponentVectors(h_prime, yn_vector,p).toArray(), h_vector.toArray()) : "h' definition is not correct";

        // g^{t_hat} h^{tau_x}
        BigInteger g_t_hat_mult_h_tau_x = PedersenCommitment.commit(g, t_hat, h, tau_x, p);

        // \delta(y, z) = (z - z^{2}) * [1^{n}, y^{n}] - z^{3} * [1^{n},2^{n}]
        BigInteger delta_yz = delta(y, z, n, q);

        BigInteger g_delta_yz = g.modPow(delta_yz, p);
        BigInteger T_1_x = T_1.modPow(x, p);
        BigInteger T_2_x_squared = T_2.modPow(x.pow(2), p);
        BigInteger V_z2_g_ = V.modPow(z.pow(2), p).multiply(g_delta_yz).mod(p).multiply(T_1_x).mod(p).multiply(T_2_x_squared).mod(p);

        //(65)
        boolean check1 = g_t_hat_mult_h_tau_x.equals(V_z2_g_);

        if (!check1) {
            System.err.println("Bulletproof.verifyStatement CHECK 1 FAILED");
            return false;
        }


        // Second check equation (66-67), see line 44 and 47 for the provers role in this
        // FIXME: TODO: this has to be a vector according to the completeness
        List<BigInteger> z_vector_negated = generateConstList(z.negate().mod(q).add(q).mod(q), n);

        // g^{-z} * (h^prime)^{z * y^n +z^2 * 2^n}
        List<BigInteger> exponentTemp_z_mult_Yn = generateListMultWithBigInt(yn_vector, z, q);
        List<BigInteger> exponentTemp_zSquared_twoN = generateListMultWithBigInt(generateList(BigInteger.TWO, n, q), z.pow(2), q);
        List<BigInteger> exponent_hprime = generateListAddVectors(exponentTemp_z_mult_Yn, exponentTemp_zSquared_twoN, q);

        // A * S^x * g^{-z} * (h^prime)^{z * y^n +z^2 * 2^n}
        BigInteger commitVectorP_left = A.multiply(PedersenCommitment.commitVector(S, x, g_vector, z_vector_negated, h_prime, exponent_hprime, p)).mod(p);

        // h^µ * g^l * (h^prime)^r
        BigInteger commitVectorP_right = PedersenCommitment.commitVector(h, mu, g_vector, l_vector, h_prime, r_vector, p);

        // A * S^x * g^{-z} * (h^prime)^{z * y^n +z^2 * 2^n} == h^µ * g^l * (h^prime)^r
        boolean check2 = commitVectorP_left.equals(commitVectorP_right);
        if (!check2) {
            System.err.println("Bulletproof.verifyStatement CHECK 2 FAILED");
            System.out.println("Bulletproof.verifyStatement         left: "+  commitVectorP_left);
            System.out.println("Bulletproof.verifyStatement        right: "+  commitVectorP_right);
            return false;
        }

        // < l , r >
        BigInteger innerProd_l_and_r = UTIL.dotProduct(l_vector, r_vector, q);

        //t_hat == \langle l, r \rangle
        boolean check3 = t_hat.compareTo(innerProd_l_and_r) == 0;
        if (!check3) {
            System.err.println("Bulletproof.verifyStatement CHECK 3 FAILED");
            return false;
        }

        return true;
    }

    public BigInteger delta(BigInteger y, BigInteger z, int n, BigInteger q) {
        List<BigInteger> _1_vector_n = generateList(BigInteger.ONE, n, q);
        List<BigInteger> _2_vector_n = generateList(BigInteger.TWO, n, q);
        List<BigInteger> y_vector_n = generateList(y, n, q);

        BigInteger innerProd_1n_2n = UTIL.dotProduct(_1_vector_n, _2_vector_n, q);
        BigInteger innerProd_1n_yn = UTIL.dotProduct(_1_vector_n, y_vector_n, q);

        BigInteger z_zSquared = z.subtract(z.pow(2).mod(q)).mod(q).add(q).mod(q); // (z-z^2)
        BigInteger z_3_mult_innerProd_1n_2n = z.pow(3).mod(q).multiply(innerProd_1n_2n).mod(q);

        return z_zSquared
                .multiply(innerProd_1n_yn).mod(q)
                .subtract(z_3_mult_innerProd_1n_2n).mod(q).add(q).mod(q);
    }

    private List<BigInteger> generateConstList(BigInteger val, int repitions) {
        return Collections.nCopies(repitions, val);
    }

    // k_vector^n = [k^0, k^1, k^2,..., k^{n-1}] (mod order)
    public List<BigInteger> generateList(BigInteger val, int n, BigInteger order) {
        List<BigInteger> vector = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            vector.add(val.pow(i).mod(order));
        }

        return vector;
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
    //IterativlyExponentiate
    private List<BigInteger> generateExponentList(List<BigInteger> list, BigInteger val, BigInteger order) {
        return list.stream().map(element -> element.modPow(val, order)).collect(Collectors.toList());
    }

    // compute x*g for vector g and biginteger x
    private List<BigInteger> generateListMultWithBigInt(List<BigInteger> list, BigInteger val, BigInteger order) {
        return list.stream()
                .map(element -> val.multiply(element).mod(order))
                .collect(Collectors.toList());
    }

    // compute a+b for vectors a and b
    private List<BigInteger> generateListAddVectors(List<BigInteger> list_a, List<BigInteger> list_b, BigInteger order) {
        return Streams.zip(list_a.stream(), list_b.stream(), (bigInt_a, bigInt_b) -> bigInt_a.add(bigInt_b).mod(order)).collect(Collectors.toList());
    }


    // Returns a list of the bits
    // m => bit representation of m
    public List<BigInteger> extractBits(BigInteger m, int n) {
        String bitsString = m.toString(2);

        if(bitsString.length() > n) {
            throw new IllegalArgumentException("Cannot extract bits. m takes more than n bits bitsString.length()=" + bitsString.length() + " >n=" + n);
        }

        //Extract bits
        List<BigInteger> bits = new ArrayList<>(n);
        int i = 0;
        for (int j = bitsString.length() - 1; j >= 0; j--) {
            boolean bit = bitsString.charAt(j) == '1';
            bits.add(bit ? BigInteger.ONE : BigInteger.ZERO);
            i++;
        }

        //Fill remaining with 0
        for (; i < n; i++) {
            bits.add(BigInteger.ZERO);
        }
        return bits;
    }

    // Mark
    public List<Integer> decomposeIntoPowersOfTwoMinusOne(BigInteger n) {
        // n to bitstring

        List<Integer> powers = new ArrayList<>();
        // While bitstring != 000000
            //bitstring++
            //Find highest i where bitstring[i]=1
            //bitstring[i]=0
            //powers.add(i)
        //return powers;
        return null;
    }

}
