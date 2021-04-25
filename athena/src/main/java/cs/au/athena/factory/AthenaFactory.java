package cs.au.athena.factory;

import cs.au.athena.athena.bulletinboard.BulletinBoardV2_0;
import cs.au.athena.athena.bulletinboard.VerifyingBulletinBoardV2_0;
import cs.au.athena.athena.distributed.AthenaDistributed;

import java.util.Random;

public interface AthenaFactory extends SigmaFactory {


    Random getRandom();

    BulletinBoardV2_0 getBulletinBoard();
    VerifyingBulletinBoardV2_0 getVerifyingBulletinBoard();
    AthenaDistributed getDistributedAthena();
}
