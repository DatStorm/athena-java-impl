package cs.au.athena.athena;

import cs.au.athena.athena.strategy.Strategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import cs.au.athena.dao.athena.*;
import cs.au.athena.elgamal.*;
import cs.au.athena.factory.AthenaFactory;


import java.lang.invoke.MethodHandles;
import java.util.*;

public class AthenaImpl implements Athena {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());
    private static final Marker MARKER = MarkerFactory.getMarker("ATHENA-IMPL");

    private final AthenaFactory athenaFactory;
    private final Strategy strategy;
    private Elgamal elgamalWithLookUpTable;
    //private BigInteger mc;
    private boolean initialised;



    public AthenaImpl(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
        this.strategy = athenaFactory.getStrategy();
        this.initialised = false;
    }

    @Override
    public ElGamalSK Setup(int tallierIndex, int nc, int kappa) {
        logger.info(MARKER, "Setup(...) => start");
        if (this.initialised) {
            System.err.println("AthenaImpl.Setup => ERROR: System not initialised call .Setup before hand");
            return null;
        }

        Random random = athenaFactory.getRandom();
        Group group = strategy.getGroup();

        this.elgamalWithLookUpTable = new Elgamal(group, nc, random);
        //this.mc = this.athenaFactory.getBulletinBoard(???).retrieveMaxCanditates();
        this.initialised = true;
        return strategy.setup(tallierIndex, nc, kappa);
    }




    @Override
    public RegisterStruct Register(PK_Vector pkv, int kappa) {
        logger.info(MARKER, "Register(...) => start");

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
        logger.info(MARKER, "Vote(...) => start");
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
    public TallyStruct Tally(int tallierIndex, SK_Vector skv, int nc, int kappa) {
        logger.info(MARKER, "Tally(...) => start");

        if (!this.initialised) {
            System.err.println("AthenaImpl.Tally => ERROR: System not initialised call .Setup before hand");
            return null;
        }



        return new AthenaTally.Builder()
                .setFactory(this.athenaFactory)
                .setElgamal(this.elgamalWithLookUpTable)
                .setTallierIndex(tallierIndex)
                .setKappa(kappa)
                .build()
                .Tally(tallierIndex, skv, nc);
    }

    @Override
    public boolean Verify(PK_Vector pkv, int kappa) {
        logger.info(MARKER, "Verify(...) => start");

        if (!this.initialised) {
            System.err.println("AthenaImpl.Verify => ERROR: System not initialised call .Setup before hand");
            return false;
        }
        return new AthenaVerify.Builder()
                .setFactory(this.athenaFactory)
                //.setMc(this.mc)
                .setKappa(kappa)
                .build()
                .Verify(pkv);
    }
}

