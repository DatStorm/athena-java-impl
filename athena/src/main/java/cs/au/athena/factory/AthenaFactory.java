package cs.au.athena.factory;

import cs.au.athena.athena.bulletinboard.BulletinBoard;
import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.strategy.Strategy;

import java.util.Random;

public interface AthenaFactory extends SigmaFactory {

    enum STRATEGY {
        SINGLE, DISTRIBUTED
    }

    Random getRandom();

    BulletinBoardV2_0 getBulletinBoard(int tallierCount);

    Strategy getStrategy();
}
