package project.athena;

import project.dao.Randomness;
import project.dao.athena.*;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import project.dao.sigma2.Sigma2Proof;
import project.dao.sigma2.Sigma2Secret;
import project.dao.sigma2.Sigma2Statement;
import project.elgamal.CipherText;
import project.elgamal.ElGamal;
import project.elgamal.ElGamalPK;
import project.elgamal.ElGamalSK;
import project.factory.AthenaFactory;
import project.sigma.Sigma1;
import project.sigma.sigma2.Sigma2;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

public class AthenaImpl implements Athena {
    private final Sigma1 simga1;
    private final Random random;
    private final Sigma2 sigma2;
    private boolean initialised;
    private ElGamal elgamal;


    public AthenaImpl(AthenaFactory athenaFactory) {
        this.simga1 = athenaFactory.getSigma1();
        this.sigma2 = athenaFactory.getSigma2();
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
        ProveKeyInfo rho = simga1.ProveKey(publicInfo, sk, randR, kappa);


        int mb = 100;
        int mc = 100;


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


        int d = 100; // TODO: Generate nonce d.
        BigInteger g = elgamal.getDescription().getG(); // TODO: Correct g ?????
        BigInteger g_d = g.pow(d);
        CipherText pd = elgamal.encrypt(g_d, pkv.pk);

        D_Vector d_vector = new D_Vector(pd, d);
        return new RegisterStruct(pd, d_vector);
    }

    private boolean verifyKey(PK_Vector pkv, int kappa) {
        return simga1.VerifyKey(new PublicInfoSigma1(kappa, pkv.pk), pkv.rho, kappa);
    }

    private boolean parsePKV(PK_Vector pkv) {
        return pkv != null && pkv.rho != null && pkv.pk != null;
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

        boolean vote_in_range = vote >= 1 && vote <= nc;
        boolean not_sub_space = false; // TODO: Check {1... nc} \not \subset \frakm{m}
        if (!vote_in_range || not_sub_space) {
            System.err.println("AthenaImpl.Vote => ERROR: v not in {1...nc}");
            return null;
        }


        // dv = vector of (pd, d)
        CipherText pd = dv.pd;
        int d = dv.d;
        int d_neg = -d;


        ElGamalPK pk = pkv.pk;
        BigInteger g = pk.getGroup().getG();


        BigInteger g_neg_d = g.pow(d_neg);
        BigInteger s = BigInteger.valueOf(this.random.nextLong()); // FIXME: Generate coins s
        CipherText c1 = elgamal.encrypt(g_neg_d, pk, s);


        BigInteger g_v = g.pow(vote);
        BigInteger t = BigInteger.valueOf(this.random.nextLong()); // FIXME: Generate coins t
        CipherText c2 = elgamal.encrypt(g_v, pk, t);


        // FIXME: Create statement
        Sigma2Proof sigma_1 = sigma2.proveCiph(null, new Sigma2Secret(BigInteger.valueOf(d_neg), s));

        // FIXME: Create statement
        // simga_2 <- ProveCiph( (pk, c2, {1,...,nc}),  (v, t), m, κ)
        Sigma2Proof sigma_2 = sigma2.proveCiph(null, new Sigma2Secret(BigInteger.valueOf(vote), t)); // TODO: Should this be g^v NOT v.

        return new Ballot(pd, c1, c2, sigma_1, sigma_2, cnt);
    }

    @Override
    public void Tally() {

    }

    @Override
    public void Verify() {

    }
}