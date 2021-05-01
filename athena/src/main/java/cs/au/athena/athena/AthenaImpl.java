package cs.au.athena.athena;

import cs.au.athena.athena.distributed.AthenaDistributed;
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
    private final AthenaDistributed distributed;
    private ElGamal elGamalWithLookUpTable;
    //private BigInteger mc;
    private boolean initialised;



    public AthenaImpl(AthenaFactory athenaFactory) {
        this.athenaFactory = athenaFactory;
        this.distributed = athenaFactory.getDistributedAthena();
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
        Group group = athenaFactory.getBulletinBoard().retrieveGroup();

        this.elGamalWithLookUpTable = new ElGamal(group, nc, random);
        this.initialised = true;
        return distributed.setup(tallierIndex, nc, kappa);
    }




    @Override
    public RegisterStruct Register(int kappa) {
        logger.info(MARKER, "Register(...) => start");

        if (!initialised) {
            logger.error("AthenaImpl.Register => ERROR: System not initialised call .Setup before hand");
            return null;
        }
        return new AthenaRegister.Builder()
                .setFactory(this.athenaFactory)
                .setElGamal(this.elGamalWithLookUpTable)
                .setKappa(kappa)
                .build()
                .Register();
    }


    @Override
    public Ballot Vote(CredentialTuple credentialTuple, int vote, int cnt, int nc, int kappa) {
        logger.info(MARKER, "Vote(...) => start");
        if (!this.initialised) {
            logger.error("AthenaImpl.Vote => ERROR: System not initialised call .Setup before hand");
            return null;
        }
        return new AthenaVote.Builder()
                .setFactory(this.athenaFactory)
                .setElGamal(this.elGamalWithLookUpTable)
                .setKappa(kappa)
                .build()
                .Vote(credentialTuple, vote, cnt, nc);
    }


    @Override
    public Map<Integer, Integer> Tally(int tallierIndex, ElGamalSK skShare, int nc, int kappa) {
        logger.info(MARKER, "Tally(...) => start");

        if (!this.initialised) {
            logger.error("AthenaImpl.Tally => ERROR: System not initialised call .Setup before hand");
            return null;
        }
        return new AthenaTally.Builder()
                .setFactory(this.athenaFactory)
                .setTallierIndex(tallierIndex)
                .setKappa(kappa)
                .build()
                .Tally(tallierIndex, skShare, nc);
    }

    @Override
    public boolean Verify( int kappa) {
        logger.info(MARKER, "Verify(...) => start");

        if (!this.initialised) {
            logger.error("AthenaImpl.Verify => ERROR: System not initialised call .Setup before hand");
            return false;
        }
        return new AthenaVerify.Builder()
                .setFactory(this.athenaFactory)
                //.setMc(this.mc)
//                .setKappa(kappa)
                .build()
                .Verify();
    }
}

