package cs.au.athena.athena;

import cs.au.athena.athena.strategy.Strategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import cs.au.athena.GENERATOR;
import cs.au.athena.dao.Randomness;
import cs.au.athena.dao.athena.*;
import cs.au.athena.dao.sigma1.ProveKeyInfo;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;


import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.util.*;

public class AthenaImpl implements Athena {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker ATHENA_IMPL_MARKER = MarkerFactory.getMarker("ATHENA-IMPL");

    private final AthenaFactory athenaFactory;
    private final Strategy strategy;
    private Elgamal elgamalWithLookUpTable;
    private BigInteger mc;
    private boolean initialised;



    public AthenaImpl(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
        this.strategy = athenaFactory.getStrategy();
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
        BulletinBoard bb = athenaFactory.getBulletinBoard();
        Random random = athenaFactory.getRandom();

        // Get the group
        Group group = strategy.getGroup(bitlength, random);

        // Create elgamal and generate keys
        ElGamalSK sk = strategy.getElGamalSK(group, random); // Dependent on the strategy this will be either the full sk or a share of it.
        ElGamalPK pk = strategy.getElGamalPK(sk); // TODO: will this be pk or h_i ?
        ProveKeyInfo rho = strategy.proveKey(pk, sk, new Randomness(random.nextLong()), kappa);

        this.elgamalWithLookUpTable = new Elgamal(group, nc, random);

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
                .setElGamal(this.elgamalWithLookUpTable)
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
                .setElGamal(this.elgamalWithLookUpTable)
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
                .setElgamal(this.elgamalWithLookUpTable)
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

