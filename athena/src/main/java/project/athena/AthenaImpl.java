package project.athena;

import org.apache.commons.lang3.tuple.Pair;
import project.UTIL;
import project.dao.Randomness;
import project.dao.athena.*;
import project.dao.mixnet.MixBallot;
import project.dao.mixnet.MixProof;
import project.dao.mixnet.MixStatement;
import project.dao.mixnet.MixStruct;
import project.dao.sigma1.ProveKeyInfo;
import project.dao.sigma1.PublicInfoSigma1;
import project.dao.sigma3.Sigma3Proof;
import project.dao.sigma4.Sigma4Proof;
import project.elgamal.*;
import project.factory.AthenaFactory;
import project.mixnet.Mixnet;
import project.sigma.Sigma1;
import project.sigma.Sigma3;
import project.sigma.Sigma4;
import project.sigma.bulletproof.Bulletproof;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class AthenaImpl implements Athena {
    private final ElectoralRoll L;

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
    private int n_vote;
    private int n_negatedPrivateCredential;

    private AthenaFactory athenaFactory;


    public AthenaImpl(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;

        this.sigma1 = athenaFactory.getSigma1();
        this.bulletProof = athenaFactory.getBulletProof();
        this.sigma3 = athenaFactory.getSigma3();
        this.sigma4 = athenaFactory.getSigma4();
        this.random = athenaFactory.getRandom();
        this.bb = athenaFactory.getBulletinBoard();

        this.L = new ElectoralRoll();
        this.initialised = false;
    }

    @Override
    public SetupStruct Setup(int kappa) throws IOException {

        if (this.initialised) {
            System.err.println("AthenaImpl.Setup => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        Gen gen = new Gen(random, kappa);
        ElGamalSK sk = gen.generate();
        ElGamalPK pk = sk.pk;
        Group group = pk.group;
        this.elgamal = gen.getElGamal(); // TODO: HER!!!!

        this.mixnet = athenaFactory.getMixnet(elgamal, pk);

        PublicInfoSigma1 publicInfo = new PublicInfoSigma1(kappa, pk);
        Randomness randR = new Randomness(this.random.nextLong());
        ProveKeyInfo rho = sigma1.ProveKey(publicInfo, sk, randR, kappa);

        this.n_vote = 3;                          // This is a function of nc. TODO: FIX THESE VALUES
        this.n_negatedPrivateCredential = 3;      // This is a function of q. TODO: FIX THESE VALUES
        int mb = 100;                             // TODO: FIX THESE VALUES
        this.mc = pk.group.q; // This needs to be within Z_q, i.e. v \in [0,..,nc-1] then mc =< q.

        List<BigInteger> g_vector_vote = group.newGenerators(n_vote, random);
        List<BigInteger> h_vector_vote = group.newGenerators(n_vote, random);
        List<BigInteger> g_vector_negatedPrivateCredential = group.newGenerators(n_negatedPrivateCredential, random);
        List<BigInteger> h_vector_negatedPrivateCredential = group.newGenerators(n_negatedPrivateCredential, random);

        bb.publishNumberOfVotes(n_vote);
        bb.publishNumberfNegatedPrivCred(n_negatedPrivateCredential);
        bb.publish_G_VectorVote(g_vector_vote);
        bb.publish_H_VectorVote(h_vector_vote);
        bb.publish_G_VectorNegPrivCred(g_vector_negatedPrivateCredential);
        bb.publish_H_VectorNegPrivCred(h_vector_negatedPrivateCredential);


        this.initialised = true;
        return new SetupStruct(new PK_Vector(pk, rho), sk, mb, mc);
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
                .setRandom(random)
                .setElgamal(elgamal)
                .setBb(bb)
                .setSigma1(this.sigma1)
                .setBulletProof(this.bulletProof)
                .setSigma3(this.sigma3)
                .setSigma4(this.sigma4)
                .setMixnet(this.mixnet)
                .build().Tally(skv,nc);
    }

    @Override
    public boolean Verify(PK_Vector pkv, int nc, Map<BigInteger, Integer> tallyOfVotes, PFStruct pf) {
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

