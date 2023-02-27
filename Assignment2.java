import java.math.BigInteger;
import java.security.*;
import java.io.*;
import java.nio.file.Files;


public class Assignment2 {

    public static class mods{
        private final BigInteger p;
        private final BigInteger q;
        private final BigInteger n;
        private final BigInteger phi;

        public mods(BigInteger p, BigInteger q, BigInteger n, BigInteger phi){
            this.p = p;
            this.q = q;
            this.n = n;
            this.phi = phi;
        }
        public BigInteger getP(){
            return p;
        }
        public BigInteger getQ(){
            return q;
        }
        public BigInteger getN(){
            return n;
        }
        public BigInteger getPhi(){
            return phi;
        }
    }
    // Generate 512 bit probable primes p and q, compute n = pq, phi(n) where gcd(e, phi(n)) = 1
    public static mods genMods(){
        BigInteger p;
        BigInteger q;
        p = BigInteger.probablePrime(512, new SecureRandom());
        q = BigInteger.probablePrime(512, new SecureRandom());
        BigInteger n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        mods modVals = new mods(p, q, n, phi);
        return modVals;
    }

    public static BigInteger getGCD(BigInteger a, BigInteger b){
        if (b.equals(BigInteger.ZERO)){
            return a;
        }
        return getGCD(b, a.mod(b));
    }
    
    // XGCD: rk = xa + yb
    // Takes input a and b and outputs x, y, rk such that rk = gcd(a,b) = xa + yb
    // Given a and n, we can compute d, x and y using XGCD d = gcd(a,n) = xa + yn
    // d = xa + yn (mod n) = xa (mod n)

    // if gcd(a,n) = b, then b = xa + yn
    // b = xa (mod n)

    // divide n by a giving q0a + r0
    // a = q1r0 + r1
    public static BigInteger getMultiInverse(BigInteger a, BigInteger b){
        BigInteger x = BigInteger.ZERO;
        BigInteger y = BigInteger.ONE;
        BigInteger rem0 = b;
        BigInteger rem1 = a;

        while (!rem1.equals(BigInteger.ZERO)){
            BigInteger q = rem0.divide(rem1);
             BigInteger p = x;
             x = y;
             y = p.subtract(q.multiply(y));
             p = rem0;
             rem0 = rem1;
             rem1 = p.subtract(q.multiply(rem1));
        }

        if (x.compareTo(BigInteger.ZERO) == -1){
            x = x.add(b);
        }

        return x;
    }
    // Instead of performing huge h(m)**d computation, use CRT to calculate this
    // n is the product of two coprime factors, p and 1
    // m can be derived from reductions of exponent d and and mod n to their factors + inverse of p mod q
    // Returns value of m (mod n)
    public static BigInteger RSADecrypt(BigInteger c, BigInteger d, BigInteger n, BigInteger p, BigInteger q){
        BigInteger d1 = d.mod(p.subtract(BigInteger.ONE));
        BigInteger d2 = d.mod(q.subtract(BigInteger.ONE));

        BigInteger a1 = c.modPow(d1,p);
        BigInteger a2 = c.modPow(d2,q);

        return (a1.add(p.multiply(getMultiInverse(p, q)).multiply(a2.subtract(a1)))).mod(n);
    }

    // v = s**e (mod n)
    public static BigInteger RSAVerify(BigInteger s, BigInteger e, BigInteger n, BigInteger p, BigInteger q){
        BigInteger e1 = e.mod(p.subtract(BigInteger.ONE));
        BigInteger e2 = e.mod(q.subtract(BigInteger.ONE));

        BigInteger a1 = s.modPow(e1, p);
        BigInteger a2 = s.modPow(e2, q);

        return (a1.add(p.multiply(getMultiInverse(p, q)).multiply(a2.subtract(a1)))).mod(n);
    }

    public static byte[] getHash(byte[] buffer){
        try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte [] hash = digest.digest(buffer);
        return hash;
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("No such encoding");
            return new byte[1];
        }
    }

    // Instead of performing huge h(m)**d computation, use CRT to calculate this

    public static void main(String args[]) throws Exception{
        mods modVals = genMods();
        BigInteger p = modVals.getP();
        BigInteger q = modVals.getQ();
        BigInteger n = modVals.getN();
        BigInteger phi = modVals.getPhi();
        BigInteger e = new BigInteger("65537", 10);
        BigInteger gcd = getGCD(e, phi);
        while (!(gcd.equals(BigInteger.ONE))){
            modVals = genMods();
            n = modVals.getN();
            phi = modVals.getPhi();
            gcd = getGCD(e, phi);
        }
        File modulus = new File("modulus.txt");
        FileWriter modToTxt = new FileWriter(modulus);
        modToTxt.write(n.toString(16));
        modToTxt.close();
        BigInteger d = getMultiInverse(e, phi);


        File msg = new File(args[0]);
        byte[] buf = Files.readAllBytes(msg.toPath());
        BigInteger c = new BigInteger(1, getHash(buf));

        BigInteger signature = RSADecrypt(c, d, n, p, q);

        BigInteger v = RSAVerify(signature, e, n, p, q);
        if (v.equals(c)){
            System.out.println(signature.toString(16));
        }



       // Convert digest into a BigInteger value to pass into signature function

}
}