package Hash;

import org.bouncycastle.crypto.OutputDigestCalculator;
import org.bouncycastle.crypto.fips.FipsDigestOperatorFactory;
import org.bouncycastle.crypto.fips.FipsSHS;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

/**
 * SHA-256
 */
public class HashCompute {

    public static byte[] getDigestBySHA_256(String msg){
        byte[] data = msg.getBytes();
        FipsDigestOperatorFactory<FipsSHS.Parameters> factory = new FipsSHS.OperatorFactory<>();

        OutputDigestCalculator<FipsSHS.Parameters> calculator = factory.createOutputDigestCalculator(FipsSHS.SHA256);

        OutputStream digestStream = calculator.getDigestStream();
        try {
            digestStream.write(data);
            digestStream.close();

            byte[] digest = calculator.getDigest();
            return digest;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String msg = "this is a test too";
        byte[] digest = getDigestBySHA_256(msg);
        if(null!=digest){
            BigInteger bigInteger = new BigInteger(1, digest);
            System.out.println(bigInteger.toString(16));
        }else{
            System.out.println("发生未知错误！");
        }

    }

}
