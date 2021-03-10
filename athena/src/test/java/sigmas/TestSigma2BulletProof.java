package sigmas;


import org.apache.commons.lang3.stream.Streams;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import project.UTIL;
import project.dao.bulletproof.BulletproofProof;
import project.dao.bulletproof.BulletproofSecret;
import project.dao.bulletproof.BulletproofStatement;
import project.elgamal.ElGamalPK;
import project.elgamal.Group;
import project.factory.Factory;
import project.factory.MainFactory;
import project.sigma.bulletproof.Bulletproof;
import project.sigma.bulletproof.PedersenCommitment;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static project.UTIL.getRandomElement;

@Tag("TestsSigma2BulletProof")
@DisplayName("Test Sigma2 BulletProof")
public class TestSigma2BulletProof {


    private ElGamalPK pk;
    private Bulletproof sigma2;
    private Random random;

    private BigInteger g;
    private BigInteger q;
    private BigInteger p;
    private BigInteger h;


    @BeforeEach
    void setUp() {
        Factory factory = new MainFactory();
        random = factory.getRandom();
        pk = factory.getPK();
        g = pk.getGroup().getG();
        p = pk.getGroup().getP();
        q = pk.getGroup().getQ();
        h = pk.getH();
        sigma2 = new Bulletproof(factory.getHash(), factory.getRandom());

        System.out.println("setup Q :" + q);
        System.out.println("setup G :" + g);
        System.out.println("setup P :" + p);
        System.out.println("setup H :" + h);

    }


    @Test
    void TestSigma2GenerateList() {
        int n = 5;


        BigInteger two = BigInteger.TWO;
        BigInteger order = BigInteger.valueOf(100L);
        List<BigInteger> list = sigma2.generateList(two, n, order);

        List<BigInteger> expecteds = Stream.of(1, 2, 4, 8, 16).map(BigInteger::valueOf).collect(Collectors.toList());
        assertArrayEquals("should be the same", expecteds.toArray(), list.toArray());


        BigInteger val = BigInteger.valueOf(5);
        BigInteger order2 = BigInteger.valueOf(100L);
        List<BigInteger> list2 = sigma2.generateList(val, n, order2);

        List<BigInteger> expecteds2 = Stream.of(1, 5, 25, 25, 25).map(BigInteger::valueOf).collect(Collectors.toList());
        assertArrayEquals("should be the same", expecteds2.toArray(), list2.toArray());


    }

    @Test
    void TestSigma2PedersenCommit() {
        BigInteger order = BigInteger.valueOf(150);

        BigInteger _g = BigInteger.valueOf(2);
        BigInteger _m = BigInteger.valueOf(4); // 2^4 = 16

        BigInteger _h = BigInteger.valueOf(3);
        BigInteger _r = BigInteger.valueOf(2); // 3^2 = 9


        BigInteger com = PedersenCommitment.commit(_g, _m, _h, _r, order);

        assertTrue(com.equals(BigInteger.valueOf(144)));


        /*
         * Test mod in commit works.
         */
        BigInteger order2 = BigInteger.valueOf(100);
        BigInteger com2 = PedersenCommitment.commit(_g, _m, _h, _r, order2);

        assertFalse(com2.equals(BigInteger.valueOf(144)));
        assertTrue(com2.equals(BigInteger.valueOf(44)));

        /*
         * Test mod works when negative commits.
         */
    }


    @Test
    void TestSigma2BulletProofFixedValues() {
        BigInteger m = BigInteger.valueOf(5);
        int n = 10;
        BigInteger q = BigInteger.valueOf(155L);

        /*
         * Challenge 1
         */
        BigInteger z = BigInteger.valueOf(136L);
        BigInteger y = BigInteger.valueOf(47L);

        /*
         * Response 1
         */
//        BigInteger t1 = BigInteger.valueOf(128L);
//        BigInteger t2 = BigInteger.valueOf(82L);

        /*
         * Challenge 2 V -> P [x]
         */
        BigInteger x = BigInteger.valueOf(47L);


        /*
         * Response 2: P -> V [tau_x, mu, t_hat, l, r]
         */
        // [1, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        List<BigInteger> a_L = sigma2.extractBits(m, n);

        // [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        List<BigInteger> _1n_vector = sigma2.generateList(BigInteger.ONE, n, q);

        // [1, 2, 4, 8, 16, 32, 64, 128, 101, 47]
        List<BigInteger> _2n_vector = sigma2.generateList(BigInteger.TWO, n, q);


        // [0, 154, 0, 154, 154, 154, 154, 154, 154, 154]
        List<BigInteger> a_R = UTIL.subtractLists(a_L, _1n_vector, q);


        // y = 47
        // [1, 47, 39, 128, 126, 32, 109, 8, 66, 2]
        List<BigInteger> yn_vector = sigma2.generateList(y, n, q);


        // [128, 82, 7, 5, 107, 78, 1, 140, 61, 128]
        List<BigInteger> s_L = UTIL.getRandomElements(q, n, random);

        // [146, 153, 39, 99, 88, 120, 66, 89, 96, 145]
        List<BigInteger> l_vector = sigma2.compute_l_vector(n, q, a_L, s_L, z, x);

        // [23, 111, 82, 88, 73, 50, 32, 67, 37, 42]
        List<BigInteger> s_R = UTIL.getRandomElements(q, n, random);

        // [94, 83, 133, 24, 113, 29, 9, 3, 46, 82]
        List<BigInteger> r_vector = sigma2.compute_r_vector(n, q, a_R, s_R, z, x, yn_vector, _2n_vector);

        // 97
        BigInteger t_hat = UTIL.dotProduct(l_vector, r_vector, q);

        // 97
        BigInteger t_hat2 = customDotProduct(l_vector, r_vector).mod(q);

        // 100 = 5 * 136^2 mod 155 = 100
        BigInteger m_z2 = m.multiply(z.pow(2)).mod(q);

        //
        List<BigInteger> t0_t1_t2 = sigma2.compute_t0_t1_t2(n, a_L, a_R, s_L, s_R, q, z, y, yn_vector, _2n_vector);

        // 122
        BigInteger t0 = t0_t1_t2.get(0);

        // 86
        BigInteger t1 = t0_t1_t2.get(1);

        // 82
        BigInteger t2 = t0_t1_t2.get(2);


        // 86 * 47 mod 155 = 12
        BigInteger t1x = t1.multiply(x).mod(q);

        // 82 * 47^2 mod 155 = 98
        BigInteger t2x2 = t2.multiply(x.pow(2)).mod(q);

        // <1^n, 2^n> = 403 mod 155 = 93
        // <1^n, y^n> = 558 mod 155 = 93
        // 62 = (136 - 136^2) * 93 - 136^3 * 93 mod 155  = 62
        BigInteger delta = sigma2.delta(y, z, n, q);

        // 7 = 100 + 62 mod 155
        BigInteger _t0 = m_z2.add(delta).mod(q);

        // t0 + t1 * x + t2 * x^2 = 7 + 12 + 98 mod 155 = 117
        BigInteger tx = t0.add(t1x).mod(q).add(t2x2).mod(q);


        assertEquals("Should be the same1", _t0, t0);

        assertEquals("Should be the same2 ", t_hat, tx);

    }

    @Test
    void TestSigma2BulletProofVerifierFixedValues() {
        BigInteger m = BigInteger.valueOf(5);
        int n = 10;
        BigInteger q = BigInteger.valueOf(155L);
        BigInteger g = BigInteger.valueOf(72L);
        BigInteger p = BigInteger.valueOf(313L); // P = 11 , q = 5
        BigInteger h = BigInteger.valueOf(137L);

        BigInteger z = BigInteger.valueOf(136L);
        BigInteger y = BigInteger.valueOf(47L);

        // [72, 72, 72, 72, 72, 72, 72, 72, 72, 72]
        List<BigInteger> g_vector = Collections.nCopies(n, g);

        // [137, 137, 137, 137, 137, 137, 137, 137, 137, 137]
        List<BigInteger> h_vector = Collections.nCopies(n, h);


        // [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        List<BigInteger> _1n_vector = sigma2.generateList(BigInteger.ONE, n, q);

        // [1, 2, 4, 8, 16, 32, 64, 128, 101, 47]
        List<BigInteger> _2n_vector = sigma2.generateList(BigInteger.TWO, n, q);

        // [1, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        List<BigInteger> a_L = sigma2.extractBits(m, n);

        // [0, 154, 0, 154, 154, 154, 154, 154, 154, 154]
        List<BigInteger> a_R = UTIL.subtractLists(a_L, _1n_vector, q);

        // y = 47
        // [1, 47, 39, 128, 126, 32, 109, 8, 66, 2]
        List<BigInteger> yn_vector = sigma2.generateList(y, n, q);

        // gamma = 128
        BigInteger gamma = BigInteger.valueOf(128L);

        // V = g^m * h^r  mod p = 72^5 * 137^128 mod 313
        // = (72^5 mod 313 = 147) * (137^128 mod 313 = 9) mod 313 = 147 * 9 mod 313 = 71
        BigInteger V = PedersenCommitment.commit(g, m, h, gamma, p);
        assertEquals("V ", BigInteger.valueOf(71L), V);

        // x = 47
        BigInteger x = BigInteger.valueOf(47L);


        // [128, 82, 7, 5, 107, 78, 1, 140, 61, 128]
        List<BigInteger> s_L_computed = UTIL.getRandomElements(q, n, random);
        List<BigInteger> s_L = Stream.of(128, 82, 7, 5, 107, 78, 1, 140, 61, 128).map(BigInteger::valueOf).collect(Collectors.toList());
        assertArrayEquals("s_L = [128, 82, 7, 5, 107, 78, 1, 140, 61, 128]", s_L.toArray(), s_L_computed.toArray());


        // [146, 153, 39, 99, 88, 120, 66, 89, 96, 145]
        List<BigInteger> l_vector = sigma2.compute_l_vector(n, q, a_L, s_L, z, x);

        // [23, 111, 82, 88, 73, 50, 32, 67, 37, 42]
        List<BigInteger> s_R_computed = UTIL.getRandomElements(q, n, random);
        List<BigInteger> s_R = Stream.of(23, 111, 82, 88, 73, 50, 32, 67, 37, 42).map(BigInteger::valueOf).collect(Collectors.toList());
        assertArrayEquals("s_R = [23, 111, 82, 88, 73, 50, 32, 67, 37, 42]", s_R.toArray(), s_R_computed.toArray());

        // [94, 83, 133, 24, 113, 29, 9, 3, 46, 82]
        List<BigInteger> r_vector = sigma2.compute_r_vector(n, q, a_R, s_R, z, x, yn_vector, _2n_vector);


        // compute t0, t1, t2
        List<BigInteger> t0_t1_t2 = sigma2.compute_t0_t1_t2(n, a_L, a_R, s_L, s_R, q, z, y, yn_vector, _2n_vector);

        // 122 =NEW VALUE=> 7
        BigInteger t0 = t0_t1_t2.get(0);
        assertEquals("t0 ", BigInteger.valueOf(7L), t0);

        // 86
        BigInteger t1 = t0_t1_t2.get(1);
        assertEquals("t1 ", BigInteger.valueOf(86L), t1);

        // 82
        BigInteger t2 = t0_t1_t2.get(2);
        assertEquals("t2 ", BigInteger.valueOf(82L), t2);


        // tau_1 = 47
        BigInteger tau_1 = BigInteger.valueOf(47L);

        // tau_2 = 102
        BigInteger tau_2 = BigInteger.valueOf(102L);

        // g^t1 * h^tau_1 mod p = 72^86 * 137^47 mod 313 = 192 * 243 mod 313 = 19.
        BigInteger T_1 = PedersenCommitment.commit(g, t1, h, tau_1, p);
        assertEquals("T_1 = 19", BigInteger.valueOf(19L), T_1);

        // g^t2 * h^tau_2 mod p = 72^82 * 137^102 mod 313 = 11 * 48 mod 313 = 215.
        BigInteger T_2 = PedersenCommitment.commit(g, t2, h, tau_2, p);
        assertEquals("T_2 = 215", BigInteger.valueOf(215L), T_2);


        // alpha = 47
        BigInteger alpha = BigInteger.valueOf(47L);

        // h^alpha * g^a_L * h^a_R mod p
        // = 137^47 * [72, 72, 72, 72, 72, 72, 72, 72, 72, 72]^[1, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        //   * [137, 137, 137, 137, 137, 137, 137, 137, 137, 137]^[0, 154, 0, 154, 154, 154, 154, 154, 154, 154] mod 313
        // = 243 * 176 * 142 mod 313 = 230
        BigInteger A_cal = PedersenCommitment.commitVector(h, alpha, g_vector, a_L, h_vector, a_R, p);
        BigInteger A = BigInteger.valueOf(230L);
        assertEquals("A = 230", A, A_cal);

        // [72, 72, 72, 72, 72, 72, 72, 72, 72, 72]^[1, 0, 1, 0, 0, 0, 0, 0, 0, 0] = 176
//        BigInteger prod = customMultProduct(g_vector, a_L, p);

        // [137, 137, 137, 137, 137, 137, 137, 137, 137, 137]^[0, 154, 0, 154, 154, 154, 154, 154, 154, 154]
        // 18446744073709551616 mod 313 = 142
//        BigInteger prod2 = customMultProduct(h_vector, a_R, p);


        BigInteger rho = BigInteger.valueOf(47L);

        // h^rho * g^s_L * h^s_R mod p
        // = 137^47 * [72, 72, 72, 72, 72, 72, 72, 72, 72, 72]^[128, 82, 7, 5, 107, 78, 1, 140, 61, 128]
        //   * [137, 137, 137, 137, 137, 137, 137, 137, 137, 137]^[23, 111, 82, 88, 73, 50, 32, 67, 37, 42] mod 313
        // = 243 * 140 * 78 mod 313 = 259
        BigInteger S_cal = PedersenCommitment.commitVector(h, rho, g_vector, s_L, h_vector, s_R, p);
        BigInteger S = BigInteger.valueOf(259L);
        assertEquals("S = 259", S, S_cal);

        // 332813391899788800 mod 313 = 140
//        BigInteger prod = customMultProduct(g_vector, s_L, p);
//        System.out.println("Prod: " + prod);

        // 12787468839814496256 mod 313 = 78
//        BigInteger prod2 = customMultProduct(h_vector, s_R, p);
//        System.out.println("Prod2: " + prod2);


        // tau_x = tau_2 * x^2 + tau_1 * x + z^2 * gamma mod q
        // = 102 * 47^2 + 47 * 47 + 136^2 * 128 mod 155
        // = 225318 + 2209 + 2367488 mod 155 = 5
        BigInteger tau_x = BigInteger.valueOf(5);
        BigInteger t_hat_cal = UTIL.dotProduct(l_vector, r_vector, q);

        // <[146, 153, 39, 99, 88, 120, 66, 89, 96, 145], [94, 83, 133, 24, 113, 29, 9, 3, 46, 82]> = 117
        BigInteger t_hat = customDotProduct(l_vector, r_vector).mod(q);
        assertEquals("t^hat = 117", t_hat, t_hat_cal);

        // alpha + rho * x mod q = 47 + 47 * 47 mod 155 = 86
        BigInteger mu = alpha.add(rho.multiply(x)).mod(q);
        assertEquals("mu = 86", BigInteger.valueOf(86), mu);


        BulletproofProof proof = new BulletproofProof(A, S, y, z, T_1, T_2, x, tau_x, t_hat, mu, l_vector, r_vector, g_vector, h_vector);
//        BulletproofProof proof = null;


        ElGamalPK pk = new ElGamalPK(new Group(g, p, q), h);
        BulletproofStatement stmnt = new BulletproofStatement(n, V, pk);

        BulletproofProof proof_computed = sigma2.proveStatement(stmnt, new BulletproofSecret(m, gamma));

        assertEquals("A", A, proof_computed.a);
//        assertEquals("S", proof.s, proof_computed.s);
        assertEquals("y", y, proof_computed.y);
        assertEquals("z", z, proof_computed.z);
//        assertEquals("T_1", T_1, proof_computed.T_1);
//        assertEquals("T_2", T_2, proof_computed.T_2);
//        assertEquals("x", x, proof_computed.x);
//        assertEquals("tau_x", tau_x, proof_computed.tau_x);
//        assertEquals("t_hat", t_hat, proof_computed.t_hat);
//        assertEquals("mu", mu, proof_computed.mu);


        /* ********
         * check 0: t0 =?= m*z^2 + \delta(y,z) mod q
         *********/
        // <1^n, 2^n> = 403 mod 155 = 93
        // <1^n, y^n> = 558 mod 155 = 93
        // 62 = (136 - 136^2) * 93 - 136^3 * 93 mod 155  = 62
        BigInteger delta = sigma2.delta(y, z, n, q);
        assertEquals("delta(y,z) = 62", BigInteger.valueOf(62), delta);

        // t0 == m*z^2 + \delta(y,z) mod q
        // 7 == 5* 136^2 + 62 = 92542 mod 155 = 7
        BigInteger m_z2_delta = m.multiply(z.pow(2)).add(delta).mod(q);
        assertEquals("t0 == m*z^2 + delta(y,z) ", t0, m_z2_delta);


        /* ********
         * check 1
         *********/
        // g^t_hat * h^tau_x mod p
        // = 72^117 * 137 ^ 5 mod 313
        // = 25 * 301 mod 313 = 13
        BigInteger check1_left_cal = PedersenCommitment.commit(g, t_hat, h, tau_x, p);
        BigInteger check1_left = BigInteger.valueOf(13L);
        assertEquals("g^{t_hat} h^{tau_x} = 13", check1_left, check1_left_cal);



        // V^(z^2 mod q) * g^(delta(y,z) mod q) * T_1^x * T_2^x^2 mod p
        // 71^(136^2 mod 155= 51) * 72^62 * 19^47 * 215^(47^2 mod 155=39) mod 313
        // 97 * 237 * 64 * 312 mod 313 = 117
        BigInteger check1_right = BigInteger.valueOf(117L);

//        assertEquals("g^{t_hat} h^{tau_x} mod p != V^z^2 * g^delta(y,z) * T_1^x * T_2^x^2 mod p", check1_left, check1_right);

        // t1 * x = 86 * 47 mod 155 = 12
        BigInteger t1x_cal = t1.multiply(x).mod(q);
        BigInteger t1x = BigInteger.valueOf(12L);
        assertEquals("t1 * x = 12", t1x, t1x_cal);

        // t2 * x^2 = 82 * 47^2 mod 155 = 82 * 2209 mod 155 = 98
        BigInteger t2_x2_cal = t2.multiply(x.pow(2).mod(q)).mod(q);
        BigInteger t2_x2 = BigInteger.valueOf(98L);
        assertEquals("t2 * x^2 = 98", t2_x2, t2_x2_cal);



//        assertEquals(g.modPow(q, p), BigInteger.ONE);


        // g^t0 * g^(t1*x + t2x^2) * h^(tau_2 * x^2 + tau_1 * x + z^2 * gamma) mod p
        // = 72^122 * 72^(12 + ??) * h^(102 * 47^2 + 47 * 47 + 136^2 * 128 ) mod 313
        // =
        BigInteger tau_xMiddle = tau_2.multiply(x.pow(2).mod(q)).add(tau_1.multiply(x).mod(q)).mod(q).add(z.pow(2).mod(q).multiply(gamma).mod(q)).mod(q);
        assertEquals("Step middle value of Tau_x does not magically change ", tau_x, tau_xMiddle);

        //  EQ 6: Fifth last step --> = 13
        // g^t0 * g^(t1*x + t2x^2) * h^(tau_2 * x^2 + tau_1 * x + z^2 * gamma) mod p
        BigInteger stepMiddle = g.modPow(t0, p).multiply(g.modPow(t1x_cal.add(t2_x2_cal).mod(q), p)).multiply(h.modPow(tau_xMiddle, p)).mod(p);
        assertEquals("g^t0 * g^(t1*x + t2x^2) * h^(tau_2 * x^2 + tau_1 * x + z^2 * gamma) mod p ", BigInteger.valueOf(13L), stepMiddle);



        BigInteger g_t0 = g.modPow(t0, p); // 206
        BigInteger marktemp = g.modPow(m.multiply(z.pow(2).mod(q)).mod(q).add(delta).mod(q), p); // 206
        assertEquals("markteemp != t0", marktemp, g_t0);


        //  EQ 7: Fourth last step --> = ?? 232 ???
        // g^(m * z^2 delta(y,z) ) * g^(t1*x + t2x^2)
        BigInteger fourthLastStepCompletenenssCheck1 = g.modPow(m.multiply(z.pow(2).mod(q)).mod(q).add(delta).mod(q), p);
        fourthLastStepCompletenenssCheck1 = fourthLastStepCompletenenssCheck1.multiply(g.modPow(t1x_cal.add(t2_x2_cal).mod(q), p)).mod(p);
        fourthLastStepCompletenenssCheck1 = fourthLastStepCompletenenssCheck1.multiply( g.modPow(tau_xMiddle,p) ).mod(p);

        //  EQ 8: Third last step --> = ??
        // g^mz^2 g^delta g^t1x g^t2x^2 h^gammaz^2 h^r1x h^r2x^2
        BigInteger thirdLastStepCompletenenssCheck1 = g.modPow(m.multiply(z.pow(2)), p)
                .multiply(g.modPow(delta, p)).mod(p)
                .multiply(g.modPow(t1.multiply(x), p)).mod(p)
                .multiply(g.modPow(t2.multiply(x.pow(2).mod(q)), p).mod(p)
                .multiply(h.modPow(gamma.multiply(z.pow(2).mod(q)), p)).mod(p)
                .multiply(h.modPow(tau_1.multiply(x), p)).mod(p)
                .multiply(h.modPow(tau_2.multiply(x.pow(2).mod(q)), p))).mod(p);

        // EQ 9: Second last step --> = 117
        BigInteger secondLastStepCompletenenssCheck1 = (g.modPow(m, p).multiply(h.modPow(gamma, p))).modPow(z.pow(2).mod(q), p);
        secondLastStepCompletenenssCheck1 = secondLastStepCompletenenssCheck1.multiply(g.modPow(delta, p)).mod(p);
        secondLastStepCompletenenssCheck1 = secondLastStepCompletenenssCheck1.multiply((g.modPow(t1, p).multiply(h.modPow(tau_1, p))).modPow(x, p)).mod(p);
        secondLastStepCompletenenssCheck1 = secondLastStepCompletenenssCheck1.multiply((g.modPow(t2, p).multiply(h.modPow(tau_2, p))).modPow(x.pow(2).mod(q), p)).mod(p);

        //////////////////////////// FROM VERIFIER ///////////////////////////////////
        BigInteger g_delta_yz = g.modPow(delta, p);
        BigInteger T_1_x = T_1.modPow(x, p);
        BigInteger T_2_x_squared = T_2.modPow(x.pow(2), p);
        BigInteger V_z2_g_ = V.modPow(z.pow(2), p).multiply(g_delta_yz).mod(p).multiply(T_1_x).mod(p).multiply(T_2_x_squared).mod(p);

        //////////////////////////// CHANGED VERSION ///////////////////////////////////
        BigInteger g_delta_yz_2 = g.modPow(delta, p);
        BigInteger T_1_x_2 = T_1.modPow(x, p);
        BigInteger T_2_x_squared_2 = T_2.modPow(x.pow(2).mod(q), p);
        BigInteger V_z2_g_2 = V.modPow(z.pow(2).mod(q), p).multiply(g_delta_yz_2).mod(p).multiply(T_1_x_2).mod(p).multiply(T_2_x_squared_2).mod(p);

        assertEquals("Step middle is not the same as check1 left ", check1_left, stepMiddle);       // 13, 13
        assertEquals("V^z^2 * g^delta(y,z) * T_1^x * T_2^x^2 mod p", check1_right, V_z2_g_2);       // 117, 117
//        assertEquals("Step middle is not the same as check1 right ", stepMiddle, check1_right);     // 13, 117
//        assertEquals("stepMiddle != V_z2_g_2", stepMiddle, V_z2_g_2);                               // 13, 117
//        assertEquals("check1_left != V_z2_g_2", check1_left, V_z2_g_2);                             // 13, 117
//         assertEquals("stepMiddle != secondLastStepCompletenenssCheck1", stepMiddle, secondLastStepCompletenenssCheck1);     // 13, 117
//         assertEquals("check1_left != secondLastStepCompletenenssCheck1", check1_left, secondLastStepCompletenenssCheck1);   // 13, 117
        assertEquals("stepMiddle != fourthLastStepCompletenenssCheck1", stepMiddle, fourthLastStepCompletenenssCheck1);
        assertEquals("fourthLastStepComplfenenssCheck1t != thirdLastStepCompletenenssCheck1", fourthLastStepCompletenenssCheck1, thirdLastStepCompletenenssCheck1);
        assertEquals("thirdLastStepCompletenenssCheck1 != secondLastStepCompletenenssCheck1", thirdLastStepCompletenenssCheck1, secondLastStepCompletenenssCheck1);
        assertEquals("secondLastStepCompletenenssCheck1 != V_z2_g_2", secondLastStepCompletenenssCheck1, V_z2_g_2);         // 117, 117
        assertEquals("Verifier != Changed version", V_z2_g_2, V_z2_g_);


        boolean verification = sigma2.verifyStatement(stmnt, proof);

        assertTrue("Should return 1", verification);
    }

    private BigInteger customMultProduct(List<BigInteger> g, List<BigInteger> a, BigInteger p) {
        assert g.size() == a.size() : g.size() + " != " + a.size();


        BigInteger res = BigInteger.ONE;

        for (int i = 0; i < g.size(); i++) {
            BigInteger val = g.get(i).modPow(a.get(i), p);
            System.out.println(i + ": " + val);
            res = res.multiply(val);
        }

        System.out.println("res:: " + res);
        return res.mod(p);
    }


    @Test
    void TestSigma2BulletProof() {
        BigInteger m = BigInteger.valueOf(5);
        int n = 10;

        // \gamma \in Z_q =[0,q-1]
        BigInteger gamma = UTIL.getRandomElement(q, random);
        BigInteger V = PedersenCommitment.commit(g, m, h, gamma, p);
        BulletproofStatement stmnt = new BulletproofStatement(n, V, pk);

        BulletproofSecret secret = new BulletproofSecret(m, gamma);
        BulletproofProof proof = sigma2.proveStatement(stmnt, secret);

        boolean verification = sigma2.verifyStatement(stmnt, proof);

        assertTrue("Should return 1", verification);

    }


    private BigInteger customDotProduct(List<BigInteger> a, List<BigInteger> b) {
        assert a.size() == b.size() : a.size() + " != " + b.size();


        BigInteger sum = BigInteger.ZERO;
        for (int i = 0; i < a.size(); i++) {

            sum = sum.add(a.get(i).multiply(b.get(i)));

        }
        return sum;
    }
}
