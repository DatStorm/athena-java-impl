package project.dao.bulletproof;

import project.elgamal.ElGamalPK;
import project.sigma.bulletproof.Bulletproof;

import java.math.BigInteger;
import java.util.List;

public class BulletproofExtensionStatement extends BulletproofStatement {
    public BigInteger H;

    private BulletproofExtensionStatement(Builder builder) {
        super(builder);
        this.H = builder.H;
    }
    
//    private BulletproofExtensionStatement(BigInteger H, BulletproofStatement bulletproofStatement) {
//        super(builder);
//        this.H = H;
//    }
//    


    public static class Builder extends BulletproofStatement.Builder<Builder> {
        private BigInteger H;

/*
        @Override
        public Builder setN(Integer n) {
            throw new UnsupportedOperationException("This should be set internally");
        }
*/
        public Builder setH(BigInteger H) {
            this.H = H;
            return this;
        }

        public BulletproofExtensionStatement build(){
            int n = Bulletproof.getN(this.H);
            super.setN(n);

            return new BulletproofExtensionStatement(this);
        }
    }


}
