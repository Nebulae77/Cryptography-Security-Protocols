import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.io.*;
import java.io.File;


public class Assignment1
{
    // Helper Functions

    public static String generateSecretValue() {
        BigInteger b = new BigInteger(1023, new SecureRandom());
        String result = b.toString(16);
        return result;
    }

    public static BigInteger generateSharedValues(BigInteger g, BigInteger b, BigInteger p){
         // convert b to binary, iterate through each bit of b and perform the for loop
         String binb = b.toString(2);
         BigInteger y = BigInteger.ONE;
         for (int i=0; i < binb.length(); i++) {
             if (binb.charAt(i) == '1') {
                 y = (y.multiply(g)).remainder(p);
             };
             g = (g.multiply(g)).remainder(p);
         };
         return y;
    }

    public static byte[] getHash(BigInteger secret){
        try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte [] hash = digest.digest(secret.toString().getBytes(StandardCharsets.UTF_8));
        return hash;
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("No such encoding");
            return new byte[1];
        }
    }

    public static byte[] generateIV(){
        byte [] IVBytes = new byte[16];
        SecureRandom IVGen = new SecureRandom();
        IVGen.nextBytes(IVBytes);
        try{
            File ivTxt = new File("IV.txt");
            FileWriter ivToTxt = new FileWriter(ivTxt);
            ivToTxt.write(new BigInteger(1, IVBytes).toString(16));
            ivToTxt.close();
        }
        catch(IOException e){
            System.out.println("Error writing to IV.txt");
        }
        return IVBytes;
    }

    public static byte[] padMessage(byte[] messageBytes){
        
        if (messageBytes.length % 16 != 0) {
            int distance = messageBytes.length % 16;
            int newSize = messageBytes.length + (16 - distance);
            byte [] paddedMessage = new byte [newSize];
            System.arraycopy(messageBytes, 0, paddedMessage, 0, messageBytes.length);
            paddedMessage[messageBytes.length] = (byte) (paddedMessage[messageBytes.length] | (1 << 7));
            return paddedMessage;
        }

        if (messageBytes.length % 16 == 0){
            int newSize = messageBytes.length + 16;
            byte [] paddedMessage = new byte [newSize];
            System.arraycopy(messageBytes, 0, paddedMessage, 0, messageBytes.length);
            paddedMessage[messageBytes.length] = (byte) (paddedMessage[messageBytes.length] | (1 << 7));
            return paddedMessage;
        }
        return new byte [16];
    }



    public static void main(String args[]) throws Exception
    {
        BigInteger p =  new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);
        BigInteger A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);

        // Public Shared Value B = g**b (mod p) 
        BigInteger b = new BigInteger(generateSecretValue(), 16);

        BigInteger B = generateSharedValues(g, b, p);
        File DH = new File("DH.txt");
        FileWriter bToTxt = new FileWriter(DH);
        bToTxt.write(b.toString(16));
        bToTxt.close();

        BigInteger s = generateSharedValues(A, b, p);
        byte [] hash = getHash(s);
        byte [] IV = generateIV();

        Key aesKey = new SecretKeySpec(hash, "AES");

        File msg = new File(args[0]);
        byte [] buf = new byte[(int) msg.length()];
        FileInputStream in = new FileInputStream(msg);
        in.read(buf);
        System.out.println(buf);
        System.out.println(buf.length);
        in.close();


        byte [] paddedMessage = padMessage(buf);
        System.out.println("Padded message " + "\n" + paddedMessage);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(IV));
        byte [] encrypted = cipher.doFinal(paddedMessage);
        String enc = Base64.getEncoder().encodeToString(encrypted);
        System.out.println(enc);

        Cipher decryptor = Cipher.getInstance("AES/CBC/NoPadding");
        decryptor.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(IV));

       byte[] plaintextBytes = decryptor.doFinal(Base64.getDecoder().decode(enc));

       // Find padding of the text by iterating through the byte array in reverse until a set bit is found
       // Set the size of the new byte array to padding - 1 to remove the set padding bit
        int padding;
        for (padding = plaintextBytes.length; padding > 0 && plaintextBytes[padding - 1] == 0; padding--);
        byte[] noPadding = new byte [padding - 1];
        System.arraycopy(plaintextBytes, 0, noPadding, 0, padding - 1);
        String plaintext =  new String(noPadding, StandardCharsets.UTF_8);
        

    }
}


