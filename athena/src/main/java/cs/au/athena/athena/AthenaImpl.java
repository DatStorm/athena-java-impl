package cs.au.athena.athena;

import cs.au.athena.athena.strategy.Strategy;
import cs.au.athena.sigma.Sigma2Pedersen;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import cs.au.athena.GENERATOR;
import cs.au.athena.dao.Randomness;
import cs.au.athena.dao.athena.*;
import cs.au.athena.dao.sigma1.ProveKeyInfo;
import cs.au.athena.dao.sigma1.PublicInfoSigma1;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;
import cs.au.athena.generator.Generator;
import cs.au.athena.generator.MockGenerator;
import cs.au.athena.mixnet.Mixnet;
import cs.au.athena.sigma.Sigma1;
import cs.au.athena.sigma.Sigma3;
import cs.au.athena.sigma.Sigma4;
import cs.au.athena.sigma.bulletproof.Bulletproof;


import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;

public class AthenaImpl implements Athena {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker ATHENA_IMPL_MARKER = MarkerFactory.getMarker("ATHENA-IMPL");

    private final AthenaFactory athenaFactory;
    private final Strategy currentStrategy;
    private Elgamal elgamal;
    private BigInteger mc;
    private boolean initialised;



    public AthenaImpl(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
        this.currentStrategy = athenaFactory.getStrategy();
        this.initialised = false;
    }

    @Override
    public ElectionSetup Setup(int nc, int kappa) {
        logger.info(ATHENA_IMPL_MARKER, "Setup(...) => start");
        if (this.initialised) {
            System.err.println("AthenaImpl.Setup => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        int bitlength = kappa * 8;
        Random random = athenaFactory.getRandom();
        BulletinBoard bb = athenaFactory.getBulletinBoard();
        Sigma1 sigma1 = athenaFactory.getSigma1();

        /**********
         * TODO: Add back the correct generator instead of mock!
         */
//        Generator gen = new Gen(random, nc, bitlength); // Because elgamal needs a larger security param
        Generator gen = new MockGenerator(random, nc, bitlength); // TODO: strategy call

        ElGamalSK sk = gen.generate();
        ElGamalPK pk = sk.pk;
        this.elgamal = gen.getElGamal();
        ProveKeyInfo rho = sigma1.ProveKey(new PublicInfoSigma1(kappa, pk), sk, new Randomness(random.nextLong()), kappa); //TODO: strategy call

        // mb, mc is upper-bound by a polynomial in the security parameter.
        // TODO: Should these be updated
        int mb = 1024; // TODO: look at the ElGamal test and find a 
        this.mc = BigInteger.valueOf(1024);


        logger.info(ATHENA_IMPL_MARKER, "Setup(...) => generators");
        List<List<BigInteger>> generators = GENERATOR.generateRangeProofGenerators(pk, nc);
        List<BigInteger> g_vector_vote = generators.get(0);
        List<BigInteger> h_vector_vote = generators.get(1);


        logger.info(ATHENA_IMPL_MARKER, "Setup(...) => publish to BB");
        bb.publishNumberOfCandidates(nc);
        bb.publish_G_VectorVote(g_vector_vote);
        bb.publish_H_VectorVote(h_vector_vote);

        PK_Vector pkv = new PK_Vector(pk, rho);
        bb.publishPKV(pkv);

        this.initialised = true;
        logger.info(ATHENA_IMPL_MARKER, "Setup(...) => done");
        return new ElectionSetup(sk);
    }




    @Override
    public RegisterStruct Register(PK_Vector pkv, int kappa) {
        logger.info(ATHENA_IMPL_MARKER, "Register(...) => start");

        if (!initialised) {
            System.err.println("AthenaImpl.Register => ERROR: System not initialised call .Setup before hand");
            return null;
        }
        return new AthenaRegister.Builder()
                .setFactory(this.athenaFactory)
                .setElGamal(this.elgamal)
                .setKappa(kappa)
                .build()
                .Register(pkv);
    }


    @Override
    public Ballot Vote(CredentialTuple credentialTuple, PK_Vector pkv, int vote, int cnt, int nc, int kappa) {
        logger.info(ATHENA_IMPL_MARKER, "Vote(...) => start");
        if (!this.initialised) {
            System.err.println("AthenaImpl.Vote => ERROR: System not initialised call .Setup before hand");
            return null;
        }
        return new AthenaVote.Builder()
                .setFactory(this.athenaFactory)
                .setElGamal(this.elgamal)
                .setKappa(kappa)
                .build()
                .Vote(credentialTuple, pkv, vote, cnt, nc);
    }


    @Override
    public TallyStruct Tally(SK_Vector skv, int nc, int kappa) {
        logger.info(ATHENA_IMPL_MARKER, "Tally(...) => start");

        if (!this.initialised) {
            System.err.println("AthenaImpl.Tally => ERROR: System not initialised call .Setup before hand");
            return null;
        }
        return new AthenaTally.Builder()
                .setFactory(this.athenaFactory)
                .setElgamal(this.elgamal)
                .setKappa(kappa)
                .build()
                .Tally(skv, nc);
    }

    @Override
    public boolean Verify(PK_Vector pkv, int kappa) {
        logger.info(ATHENA_IMPL_MARKER, "Verify(...) => start");

        if (!this.initialised) {
            System.err.println("AthenaImpl.Verify => ERROR: System not initialised call .Setup before hand");
            return false;
        }
        return new AthenaVerify.Builder()
                .setFactory(this.athenaFactory)
                .setMc(this.mc)
                .setKappa(kappa)
                .build()
                .Verify(pkv);
    }

}

