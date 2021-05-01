package cs.au.athena.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

public class PowerModCalculater {


    public static void main(String[] args) throws IOException {


        while (true) {
// Enter data using BufferReader
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            System.out.println("---".repeat(30));
            System.out.println("Computing b^e mod m");

            System.out.print("Base     b: ");
            // Reading data using readLine
            String base = reader.readLine();
            BigInteger baseBig = new BigInteger(base);


            System.out.print("Exponent e: ");
            // Reading data using readLine
            String exponent = reader.readLine();
            BigInteger exponentBig = new BigInteger(exponent);


            System.out.print("Mod      m: ");
            // Reading data using readLine
            String mod = reader.readLine();
            BigInteger modBig = new BigInteger(mod);

            BigInteger res = baseBig.modPow(exponentBig,modBig);

            System.out.printf("%d^%d mod %d \n", baseBig,exponentBig,modBig);
            System.out.printf("= %d", res);
        }
    }
}
