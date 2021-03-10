package project.athena;

import project.dao.Randomness;
import project.dao.athena.*;
import project.dao.bulletproof.BulletproofProof;
import project.dao.bulletproof.BulletproofSecret;
import project.dao.bulletproof.BulletproofStatement;
import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixStruct;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import project.dao.sigma2.Sigma2Proof;
import project.dao.sigma2.Sigma2Secret;
import project.dao.sigma2.Sigma2Statement;
import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.CipherText;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.AthenaFactory;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;
import project.sigma.sigma2.Sigma2;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

public class AthenaImpl implements Athena {
    private final Sigma1 sigma1;
    private final Random random;
    //    private final Sigma2 sigma2;
    private final Bulletproof bulletProof;

    private final Sigma3 sigma3;
    private final Sigma4 sigma4;
    private final Mixnet mixnet;
    private boolean initialised;
    private ElGamal elgamal;
    private int mc;


    public AthenaImpl(AthenaFactory athenaFactory) {
        this.sigma1 = athenaFactory.getSigma1();
//        this.sigma2 = athenaFactory.getSigma2();
        bulletProof = athenaFactory.getBulletProof();
        this.sigma3 = athenaFactory.getSigma3();
        this.sigma4 = athenaFactory.getSigma4();
        this.mixnet = athenaFactory.getMixnet();
        this.random = athenaFactory.getRandom();

        this.initialised = false;
    }

    @Override
    public SetupStruct Setup(int kappa) throws IOException {

        Gen gen = new Gen(random, kappa);
        ElGamalSK sk = gen.generate();
        ElGamalPK pk = sk.getPK();
        this.elgamal = gen.getElGamal();

        PublicInfoSigma1 publicInfo = new PublicInfoSigma1(kappa, pk);
        Randomness randR = new Randomness(this.random.nextLong());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfo, sk, randR, kappa);


        int mb = 100;
        this.mc = 100;


        this.initialised = true;
        return new SetupStruct(new PK_Vector(pk, rho), sk, mb, mc);
    }

    @Override
    public RegisterStruct Register(PK_Vector pkv, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Register => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        if (!parsePKV(pkv)) {
            System.err.println("AthenaImpl.Register => ERROR: pkv null");
            return null;
        }

        if (!verifyKey(pkv, kappa)) {
            System.err.println("AthenaImpl.Register => ERROR: VerifyKey(...) => false");
            return null;
        }


        int d = gernerateNonce();
        BigInteger g = elgamal.getDescription().getG(); // TODO: Correct g ?????
        BigInteger q = elgamal.getDescription().getQ(); // TODO: COORECT ??
        BigInteger g_d = g.pow(d).mod(q);
        CipherText pd = elgamal.encrypt(g_d, pkv.pk);

        D_Vector d_vector = new D_Vector(pd, d);
        return new RegisterStruct(pd, d_vector);
    }

    private int gernerateNonce() {
        // TODO: Generate nonce d.
        return 100;
    }

    @Override
    public Ballot Vote(D_Vector dv, PK_Vector pkv, int vote, int cnt, int nc, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Vote => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        if (!parsePKV(pkv)) {
            System.err.println("AthenaImpl.Vote => ERROR: pkv null");
            return null;
        }

        if (!verifyKey(pkv, kappa)) {
            System.err.println("AthenaImpl.Vote => ERROR: VerifyKey(...) => false");
            return null;
        }


        // TODO: Changed s.t. instead of checking v \in {1,...,nc} check {0,...,nc-1}
//        boolean vote_in_range = vote >= 1 && vote <= nc;
        boolean vote_in_range = vote >= 0 && vote <= nc - 1;
        boolean not_sub_space = false; // TODO: Check {1... nc} \not \subset \frakm{m}
        if (!vote_in_range || not_sub_space) {
            System.err.println("AthenaImpl.Vote => ERROR: v not in {1...nc}");
            return null;
        }


        // dv = vector of (pd, d)
        CipherText pd = dv.pd;


        ElGamalPK pk = pkv.pk;
        BigInteger g = pk.getGroup().getG();
        BigInteger p = pk.getGroup().getP();
        BigInteger q = pk.getGroup().getQ();

        // -d mod q
        BigInteger d_neg = BigInteger.valueOf(100).negate(); // TODO: Generate nonce.
        d_neg = d_neg.mod(q).add(q).mod(q);


        // g^{-d}
        //BigInteger g_neg_d = g.modPow(d_neg, p); // not in Z_q
        BigInteger s = BigInteger.valueOf(this.random.nextLong()); // FIXME: Generate coins s
        CipherText c1 = elgamal.encrypt(d_neg, pk, s);


        BigInteger v_big = BigInteger.valueOf(vote);
        BigInteger t = BigInteger.valueOf(this.random.nextLong()); // FIXME: Generate coins t
        CipherText c2 = elgamal.encrypt(v_big, pk, t);


        // FIXME: Create statement
//        Sigma2Statement sigma2_statment_1 = new Sigma2Statement(c1, a, b, pk);
//        Sigma2Proof sigma_1 = sigma2.proveCiph(sigma2_statment_1, new Sigma2Secret(d_neg, s));

        BulletproofStatement stmnt_1 = null;
//        BulletproofStatement stmnt_1 = new BulletproofStatement(m,c1,pk);
        BulletproofSecret secret_1 = new BulletproofSecret(d_neg, s);
        BulletproofProof sigma_1_bulletProof = bulletProof.proveStatement(stmnt_1, secret_1);

        // FIXME: Create statement
        // simga_2 <- ProveCiph( (pk, c2, {1,...,nc}),  (v, t), m, κ)
//        Sigma2Statement sigma2_statment_2 = new Sigma2Statement(c2, BigInteger.ONE, BigInteger.valueOf(nc), pk);
//        Sigma2Proof sigma_2 = sigma2.proveCiph(sigma2_statment_2, new Sigma2Secret(v_big, t)); // TODO: Should this be g^v NOT v.

        BulletproofStatement stmnt_2 = null;
        BulletproofSecret secret_2 = new BulletproofSecret(v_big, t);
        BulletproofProof sigma_2_bulletProof = bulletProof.proveStatement(stmnt_2, secret_2);

        return new Ballot(pd, c1, c2, sigma_1_bulletProof, sigma_2_bulletProof, cnt);
    }

    @Override
    public TallyStruct Tally(SK_Vector skv, BullitinBoard bb, int nc, ElectoralRoll L, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Tally => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        ElGamalSK sk = skv.sk;

        /* ********
         * Step 1: Remove invalid ballots
         *********/
        List<Ballot> finalBallots = removeInvalidBallots(bb);



        /* ********
         * Step 2: Mix final votes
         *********/
        List<PFRStruct> pfr = new ArrayList<>();
        Map<MapAKey, MapAValue> A = new HashMap<>();

        int nonce_n = 100; // TODO: generate nonce n.

        int ell = finalBallots.size();
        for (int i = 0; i < ell; i++) {
            Ballot bi = finalBallots.get(i);

            CipherText ci_prime = homoCombination(bi.get2(), nonce_n);

            // N <- Dec(sk, ci_prime)
            BigInteger N = elgamal.decrypt(ci_prime, sk);

            MapAKey key_i = new MapAKey(bi.get1(), N);
            A.put(key_i, countBallot(bi, A.get(key_i))); // count ballots t <- A.get(key_i)

//            Sigma3Proof sigma = sigma3.proveDecryption(); // TODO: HER!!
            Sigma3Proof sigma = null; // TODO: HER!!

            if (pfr.size() > 0) {
                // Prove c0 i−1 and c0 i are derived by iterative
                // homomorphic combination wrt nonce n
                CipherText ci_1_prime = null;
                List<CipherText> listCombined = Arrays.asList(ci_1_prime, ci_prime);
                List<CipherText> listCipherTexts = Arrays.asList(finalBallots.get(i - 1).get2(), bi.get2());
                Sigma4Proof omega = sigma4.proveCombination(sk, listCombined, listCipherTexts, nonce_n, kappa);
                pfr.add(new PFRStruct(ci_prime, N, sigma, omega));
            } else {
                pfr.add(new PFRStruct(ci_prime, N, sigma)); // TODO: Omega set to null....
            }
        }

        List<MixBallot> B = pairwiseMixnet(A);




        /* ********
         * Step 3: Reveal eligible votes
         *********/

        // initialise b as a zero filled vector of length nc
        Map<BigInteger, Integer> ballotVotes = new HashMap<>(nc);

        List<PFDStruct> pfd = new ArrayList<>();
        List<Integer> nonces_n1_nB = generateNonces(B.size());
        for (MixBallot mixedBallot : B) {
            CipherText c1 = mixedBallot.getC1();
            CipherText c2 = mixedBallot.getC2();

            int pdf_size_add1 = pfd.size() + 1;
            Integer n_pdfSize_add1 = nonces_n1_nB.get(pdf_size_add1);
            CipherText c_prime = homoCombination(c1, n_pdfSize_add1);
            BigInteger m = elgamal.decrypt(c_prime, sk);
            Sigma4Proof omega = sigma4.proveCombination(sk, Collections.singletonList(c_prime), Collections.singletonList(c1), n_pdfSize_add1, kappa);

            Sigma3Proof sigma_1 = sigma3.proveDecryption(c_prime, m, sk, kappa);

            if (m.equals(BigInteger.ONE)) {
                // c1 encrypts g0, hence, is derived from homo
                // comb of pub cred and enc of neg private cred
                BigInteger v = elgamal.decrypt(c2, sk);

                // Check that map all ready has some votes for that candidate.
                if (ballotVotes.containsKey(v)) {
                    Integer totalVotes = ballotVotes.get(v);
                    ballotVotes.put(v, totalVotes + 1);
                } else {
                    ballotVotes.put(v, 1);
                }

                Sigma3Proof sigma_2 = sigma3.proveDecryption(c2, v, sk, kappa);
                PFDStruct value = new PFDStruct(c_prime, v, omega, sigma_1, sigma_2);

                // pfd <- pfd || (c', v, omega, sigma_1, sigma_2);
                if (!pfd.contains(value)) {
                    pfd.add(value);
                }

            } else {
                // m != 1
                PFDStruct value = new PFDStruct(c_prime, m, omega, sigma_1); // FIXME: sigma_2 sat to null.
                if (!pfd.contains(value)) {
                    pfd.add(value);
                }
            }


        }

        return new TallyStruct(ballotVotes, new PFStruct(pfr, B, pfd));
    }


    @Override
    public boolean Verify(PK_Vector pkv, BullitinBoard bb, int nc, ElectoralRoll l, Map<BigInteger, Integer> b, PFStruct pf, int kappa) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Verify => ERROR: System not initialised call .Setup before hand");
            return false;
        }


        if (!parsePKV(pkv)) {
            System.err.println("AthenaImpl.Verify => ERROR: pkv null");
            return false;
        }
        ElGamalPK pk = pkv.pk;

        if (b.size() != nc) {
            System.err.println("AthenaImpl.Verify => ERROR: b.size() != nc");
            return false;
        }

        if (!verifyKey(pkv, kappa)) {
            System.err.println("AthenaImpl.Verify => ERROR: VerifyKey(...) => false");
            return false;
        }

        if (!(nc <= this.mc)) {
            System.err.println("AthenaImpl.Verify => ERROR: nc > mc");
            return false;
        }


        /* ********
         * Check 1: Check ballot removal
         *********/
        // check {b_1,...,b_\ell} = Ø implies b is a zero-filled vector. TODO <---
        List<Ballot> finalBallots = removeInvalidBallots(bb);



        /* ********
         * Check 2: Check mix
         *********/
        int ell = finalBallots.size();

        if (!parsePF(pf)) {
            System.err.println("AthenaImpl.Verify => ERROR: pf parsed as null");
            return false;
        }

        List<PFRStruct> pfr = pf.pfr;

        for (int i = 0; i < ell; i++) {
            PFRStruct pfr_data = pfr.get(i);
            CipherText ci_prime = pfr_data.ci_prime;
            BigInteger Ni = pfr_data.n;
            Sigma3Proof sigma_i = pfr_data.sigma;


            boolean veri_dec = sigma3.verifyDecryption(ci_prime, Ni, pk, sigma_i, kappa);
            if (!veri_dec) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption");
                return false;
            }
        }

        // NOTE INDEX IS DIFFERENT!!
        for (int i = 1; i <= ell; i++) {

            CipherText ci_1_prime = pfr.get(i - 1).ci_prime; // the combined ballot before!
            CipherText ci_prime = pfr.get(i).ci_prime;

            Sigma4Proof omega_i = pfr.get(i).omega;

            Ballot bi = finalBallots.get(i);
            Ballot bi_1 = finalBallots.get(i - 1); // the ballot before!


            List<CipherText> combined = Arrays.asList(ci_1_prime, ci_prime);
            List<CipherText> listOfBi_2 = Arrays.asList(bi_1.get2(), bi.get2());
            boolean veri_comb = sigma4.verifyCombination(pk, combined, listOfBi_2, omega_i, kappa);
            if (!veri_comb) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma4.verifyCombination([c'_i-1, c'_i], [b_i-1, b_i])");
                return false;
            }


        }


        // initialise A as an empty map from pairs to triples
        Map<MapAKey, MapAValue> A = new HashMap<>();

        for (int i = 0; i < ell; i++) {
            Ballot bi = finalBallots.get(i);

            BigInteger Ni = pfr.get(i).n;
            MapAKey key_i = new MapAKey(bi.get1(), Ni);
            A.put(key_i, countBallot(bi, A.get(key_i))); // count ballots t <- A.get(key_i)
        }


        // TODO: CHECK THIS
        // check B was output by the mix applied in Step 2 of algorithm
        // Tally on input of the pairs of ciphertexts in A
        List<MixBallot> B = pairwiseMixnet(A);

        if (!Arrays.deepEquals(B.toArray(), pf.b.toArray())) {
            System.err.println("AthenaImpl.Verify => ERROR: Mixnet(A) => B not mixed in valid format");
            return false;
        }



        /* ********
         * Check 3: Check revelation
         *********/
        List<PFDStruct> pfd = pf.pfd;
        if (pfd.size() != B.size()) {
            System.err.println("AthenaImpl.Verify => ERROR: pfd.size() != |B|");
            return false;
        }

        List<Integer> validBallotsIndices = new ArrayList<>();
        List<Integer> invalidBallotsIndices = new ArrayList<>();
        for (int v = 1; v <= nc; v++) {

            // should exist in map
            BigInteger bigV = BigInteger.valueOf(v);
            if (b.containsKey(bigV)) {
                validBallotsIndices.add(v);
            } else {
                invalidBallotsIndices.add(v);
            }
        }


        for (Integer i : validBallotsIndices) { // TODO: Hacky does this really work!!
//        for (int i = 0; i < B.size(); i++) {
            MixBallot mxB = B.get(i);
            CipherText c1 = mxB.getC1();
            CipherText c2 = mxB.getC2();

            PFDStruct pfd_data = pfd.get(i);
            CipherText c_prime = pfd_data.c_prime;
            Sigma4Proof omega = pfd_data.omega;

            boolean veri_comb = sigma4.verifyCombination(pk, Collections.singletonList(c_prime), Collections.singletonList(c1), omega, kappa);
            if (!veri_comb) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma4.verifyCombination(c', c1)");
                return false;
            }
            Sigma3Proof sigma_1 = pfd_data.sigma_1;
            boolean veri_dec_1 = sigma3.verifyDecryption(c_prime, BigInteger.ONE, pk, sigma_1, kappa);
            if (!veri_dec_1) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption(c', 1)");
                return false;
            }

            BigInteger v = pfd_data.mv;
            Sigma3Proof sigma_2 = pfd_data.sigma_2;
            boolean veri_dec_v = sigma3.verifyDecryption(c2, v, pk, sigma_2, kappa);
            if (!veri_dec_v) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption(c2, v)");
                return false;
            }
        }

        // and for each remaining integer i \in {1,..., |B|}
        for (Integer i : invalidBallotsIndices) { // TODO: Hacky does this really work!!
//        for (int i = 0; i < B.size(); i++) {
            MixBallot mxB = B.get(i);
            CipherText c1 = mxB.getC1();
            CipherText c2 = mxB.getC2();

            PFDStruct pfd_data = pfd.get(i);
            CipherText c_prime = pfd_data.c_prime;
            Sigma4Proof omega = pfd_data.omega;

            boolean veri_comb = sigma4.verifyCombination(pk, Collections.singletonList(c_prime), Collections.singletonList(c1), omega, kappa);
            if (!veri_comb) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma4.verifyCombination(c', c1)");
                return false;
            }

            BigInteger m = pfd_data.mv;
            Sigma3Proof sigma_1 = pfd_data.sigma_1;
            boolean veri_dec_m = sigma3.verifyDecryption(c_prime, m, pk, sigma_1, kappa);
            if (!veri_dec_m) {
                System.err.println("AthenaImpl.Verify => ERROR: Sigma3.verifyDecryption(c', m)");
                return false;
            }

            if (!m.equals(BigInteger.ONE)) {
                System.err.println("AthenaImpl.Verify => ERROR: m == 1");
                return false;
            }
        }


        return true;
    }


    private MapAValue countBallot(Ballot bi, MapAValue t) {
        int cnt = bi.get6();

        MapAValue value = null;
        if (t == null || t.get1() < cnt) {
            // Update the map if A[(bi[1]; N)] is empty
            // or contains a lower counter
            value = new MapAValue(cnt, bi.get1().combine(bi.get2()), bi.get3());
        } else if (t.get1() == cnt) {
            // Disregard duplicate counters
            value = new MapAValue(cnt, null, null); // (bi[6], \bot, \bot)
        } else {
            System.err.println("AthenaImpl.countBallot => This case should never happen");
        }

        return value;
    }


    private List<Ballot> removeInvalidBallots(BullitinBoard bb) {
        List<Ballot> finalBallots = bb.getBallots();
        for (Ballot b : bb.getBallots()) {

            CipherText pd = b.pd; // TODO: Verify in L

            // VerCiph( (pk, g, c1, M), sigma1, m, kappa)
//            Sigma2Statement statement = new Sigma2Statement(c, a, b, pk);
//            boolean verify_c1 = sigma2.verifyCipher(null, b.sigma_1);
            BulletproofStatement stmnt_1 = null;
            boolean verify_c1 = bulletProof.verifyStatement(stmnt_1, b.sigma_1);

            // remove invalid ballots.
            if (!verify_c1) {
                finalBallots.remove(b);
            }


            // VerCiph( (pk, c2, {1,...,nc}), sigma2, m, kappa)
//            boolean verify_c2 = sigma2.verifyCipher(null, b.sigma_2);
            BulletproofStatement stmnt_2 = null;
            boolean verify_c2 = bulletProof.verifyStatement(stmnt_2, b.sigma_2);

            // remove invalid ballots.
            if (!verify_c2) {
                finalBallots.remove(b);
            }

        }
        return finalBallots;
    }


    private boolean verifyKey(PK_Vector pkv, int kappa) {
        return sigma1.VerifyKey(new PublicInfoSigma1(kappa, pkv.pk), pkv.rho, kappa);
    }

    private boolean parsePKV(PK_Vector pkv) {
        return pkv != null && pkv.rho != null && pkv.pk != null;
    }

    private boolean parsePF(PFStruct pf) {
        return pf != null && pf.pfd != null && pf.b != null && pf.pfr != null;
    }


    private List<Integer> generateNonces(int size_B) {
        List<Integer> nonces_n1_nB = new ArrayList<>();
        for (int i = 0; i < size_B; i++) {
            nonces_n1_nB.add(i);
        }
        Collections.shuffle(nonces_n1_nB);
        return nonces_n1_nB;
    }

    private List<MixBallot> pairwiseMixnet(Map<MapAKey, MapAValue> A) {

        List<MixBallot> ballots = new ArrayList<>();
        for (MapAValue val : A.values()) {
            ballots.add(val.toMixBallot());
        }

        MixStruct mixStruct = mixnet.mix(ballots);

        List<MixBallot> mixedBallots = mixStruct.mixedBallots;

        // TODO: WHAT ABOUT PROOF AND STATEMENT
//        MixStatement statement = new MixStatement(ballots, mixedBallots);
//        MixProof proof = mixnet.proveMix(statement, mixStruct.secret);
//        boolean verification = mixnet.verify(statement, proof);

        return mixedBallots;
    }

    private CipherText homoCombination(CipherText c1, int n) {
        return c1; // TODO: Hacky....
    }
}
