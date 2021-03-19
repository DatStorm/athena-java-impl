package project.athena;

import project.dao.Randomness;
import project.dao.athena.*;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import project.elgamal.*;
import project.factory.AthenaFactory;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.*;

public class AthenaImpl implements Athena {

    private final Sigma1 sigma1;
    private final Bulletproof bulletProof;
    private final Sigma3 sigma3;
    private final Sigma4 sigma4;
    private Mixnet mixnet;

    private final BulletinBoard bb;
    private final Random random;
    private ElGamal elgamal;

    private boolean initialised;
    private BigInteger mc;

    private final AthenaFactory athenaFactory;


    public AthenaImpl(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
        this.sigma1 = athenaFactory.getSigma1();
        this.bulletProof = athenaFactory.getBulletProof();
        this.sigma3 = athenaFactory.getSigma3();
        this.sigma4 = athenaFactory.getSigma4();
        this.random = athenaFactory.getRandom();
        this.bb = athenaFactory.getBulletinBoard();
        this.initialised = false;
    }

    @Override
    public ElectionSetup Setup(int kappa, int nc) {
        if (this.initialised) {
            System.err.println("AthenaImpl.Setup => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        Gen gen = new Gen(random, nc, kappa);
        ElGamalSK sk = gen.generate();
        ElGamalPK pk = sk.pk;
        Group group = pk.group;
        this.elgamal = gen.getElGamal();

        this.mixnet = athenaFactory.getMixnet(elgamal, pk);

        PublicInfoSigma1 publicInfo = new PublicInfoSigma1(kappa, pk);
        Randomness randR = new Randomness(this.random.nextLong());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfo, sk, randR, kappa);

        BigInteger H = BigInteger.valueOf(nc-1); // H = nc - 1
        int n1 = Bulletproof.getN(H);
        int n2 = Bulletproof.getN(group.q) - 1; //q.bitlength()-1

        // mc is upper-bound by a polynomial in the security parameter
        // i.e kappa^2 = 2048^2 = 4194304 candidates.
        int mb = (int) Math.pow(kappa, 2.0); // TODO: FIX THESE VALUES
        this.mc = BigInteger.valueOf(kappa).pow(2); // TODO: FIX THESE VALUES

        List<BigInteger> g_vector_vote = group.newGenerators(n1, random);
        List<BigInteger> h_vector_vote = group.newGenerators(n1, random);
        List<BigInteger> g_vector_negatedPrivateCredential = group.newGenerators(n2, random);
        List<BigInteger> h_vector_negatedPrivateCredential = group.newGenerators(n2, random);

        bb.publishNumberOfCandidates(nc);

        bb.publish_G_VectorVote(g_vector_vote);
        bb.publish_H_VectorVote(h_vector_vote);
        bb.publish_G_VectorNegPrivCred(g_vector_negatedPrivateCredential);
        bb.publish_H_VectorNegPrivCred(h_vector_negatedPrivateCredential);

        PK_Vector pkv = new PK_Vector(pk, rho);
        bb.publishPKV(pkv);

        this.initialised = true;
        return new ElectionSetup(pkv, sk, mb, mc, nc);
    }


    @Override
    public RegisterStruct Register(PK_Vector pkv) {
        if (!initialised) {
            System.err.println("AthenaImpl.Register => ERROR: System not initialised call .Setup before hand");
            return null;
        }
        return new AthenaRegister.Builder()
                .setBB(this.bb)
                .setRandom(this.random)
                .setSigma1(this.sigma1)
                .setElGamal(this.elgamal)
                .build()
                .Register(pkv);
    }


    @Override
    public Ballot Vote(CredentialTuple credentialTuple, PK_Vector pkv, int vote, int cnt, int nc) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Vote => ERROR: System not initialised call .Setup before hand");
            return null;
        }
        return new AthenaVote.Builder()
                .setSigma1(this.sigma1)
                .setBulletProof(this.bulletProof)
                .setRandom(this.random)
                .setElGamal(this.elgamal)
                .setBB(this.bb)
                .build()
                .Vote(credentialTuple, pkv, vote, cnt, nc);
    }


    @Override
    public TallyStruct Tally(SK_Vector skv, int nc) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Tally => ERROR: System not initialised call .Setup before hand");
            return null;
        }
        return new AthenaTally.Builder()
                .setRandom(this.random)
                .setElgamal(this.elgamal)
                .setBb(this.bb)
                .setSigma1(this.sigma1)
                .setBulletProof(this.bulletProof)
                .setSigma3(this.sigma3)
                .setSigma4(this.sigma4)
                .setMixnet(this.mixnet)
                .build()
                .Tally(skv,nc);
    }

    @Override
    public boolean Verify(PK_Vector pkv, int nc, Map<Integer, Integer> tallyOfVotes, PFStruct pf) {
        if (!this.initialised) {
            System.err.println("AthenaImpl.Verify => ERROR: System not initialised call .Setup before hand");
            return false;
        }
        return new AthenaVerify.Builder()
                .setSigma1(this.sigma1)
                .setBulletproof(this.bulletProof)
                .setSigma3(this.sigma3)
                .setSigma4(this.sigma4)
                .setMixnet(this.mixnet)
                .setBB(this.bb)
                .setMc(this.mc)
                .build()
                .Verify(pkv, nc, tallyOfVotes, pf);
    }

}

