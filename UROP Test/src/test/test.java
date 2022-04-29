package test;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Random;

import org.bouncycastle.util.encoders.Hex;

import net.i2p.util.NativeBigInteger;

public class test {
	final static BigInteger TWO = BigInteger.valueOf(2); // constant for scalar operations
	final static BigInteger THREE = BigInteger.valueOf(3);
	static BigInteger a = new BigInteger("6277101735386680763835789423207666416083908700390324961276");
	public static void main(String[] args) throws GeneralSecurityException {
		run();

	}
	private static void run() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		//Initiate the two KeyPairs
		KeyPair k1=generateRandom();
		KeyPair k2=generateRandom();
		ECPublicKey PublicKey1=(ECPublicKey)k1.getPublic();
		ECPublicKey PublicKey2=(ECPublicKey)k2.getPublic();
		ECPrivateKey PrivateKey1=(ECPrivateKey)k1.getPrivate();
		ECPrivateKey PrivateKey2=(ECPrivateKey)k2.getPrivate();
		System.out.println("The first KeyPair: ");
		System.out.println(PublicKey1);
		System.out.println("Private Key is: "+getPrivateKeyAsHex(PrivateKey1));
		System.out.println("---------------------------------------");
		System.out.println("The second KeyPair: ");
		System.out.println(PublicKey2);
		System.out.println("Private Key is: "+getPrivateKeyAsHex(PrivateKey2));
		//Transform the two PublicKeys into two EC points
		ECPoint p1=PublicKey1.getW();
		ECPoint p2=PublicKey1.getW();
		
		//Addition
		ECPoint additionResult=addPoint(p1,p2,PrivateKey1.getParams().getCurve());
		System.out.println("---------------------------------------");
		System.out.println("add two points");
		System.out.println("---------------------------------------");
		System.out.println("After addition, X value: "+additionResult.getAffineX());
		System.out.println("After addition, Y value: "+additionResult.getAffineY());
		//ScalarMultiply
		ECPoint scalarResult=scalmult(p1,a,PrivateKey1.getParams().getCurve());
		System.out.println("---------------------------------------");
		System.out.println("Scalar multiplication by "+a);
		System.out.println("---------------------------------------");
		System.out.println("After scalar multiplication, X value: "+scalarResult.getAffineX());
		System.out.println("After scalar multiplication, Y value: "+scalarResult.getAffineY());
		
		
		
	}
	public static KeyPair generateRandom() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
		keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	
	//These two functions below are used to print the privateKey
    private static String getPrivateKeyAsHex(PrivateKey privateKey) {

        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        byte[] privateKeyBytes = new byte[24];
        writeToStream(privateKeyBytes, 0, ecPrivateKey.getS(), 24);

        return Hex.toHexString(privateKeyBytes);
    }
    private static void writeToStream(byte[] stream, int start, BigInteger value, int size) {
        byte[] data = value.toByteArray();
        int length = Math.min(size, data.length);
        int writeStart = start + size - length;
        int readStart = data.length - length;
        System.arraycopy(data, readStart, stream, writeStart, length);
    }
    private static ECPoint doublePoint(ECPoint r, EllipticCurve curve) {
    	  if (r.equals(ECPoint.POINT_INFINITY)) 
    	    return r;
    	  BigInteger slope = (r.getAffineX().pow(2)).multiply(THREE);
    	  slope = slope.add(curve.getA());
    	  BigInteger prime = ((ECFieldFp) curve.getField()).getP();
    	  // use NBI modInverse();
    	  BigInteger tmp = r.getAffineY().multiply(TWO);
    	  tmp = new NativeBigInteger(tmp);
    	  slope = slope.multiply(tmp.modInverse(prime));
    	  BigInteger xOut = slope.pow(2).subtract(r.getAffineX().multiply(TWO)).mod(prime);
    	  BigInteger yOut = (r.getAffineY().negate()).add(slope.multiply(r.getAffineX().subtract(xOut))).mod(prime);
    	  ECPoint out = new ECPoint(xOut, yOut);
    	  return out;
    	}
    private static ECPoint addPoint(ECPoint r, ECPoint s, EllipticCurve curve) {
    	  if (r.equals(s))
    	    return doublePoint(r, curve);
    	  else if (r.equals(ECPoint.POINT_INFINITY))
    	    return s;
    	  else if (s.equals(ECPoint.POINT_INFINITY))
    	    return r;
    	  BigInteger prime = ((ECFieldFp) curve.getField()).getP();
    	  // use NBI modInverse();
    	  BigInteger tmp = r.getAffineX().subtract(s.getAffineX());
    	  tmp = new NativeBigInteger(tmp);
    	  BigInteger slope = (r.getAffineY().subtract(s.getAffineY())).multiply(tmp.modInverse(prime)).mod(prime);
    	  slope = new NativeBigInteger(slope);
    	  BigInteger xOut = (slope.modPow(TWO, prime).subtract(r.getAffineX())).subtract(s.getAffineX()).mod(prime);
    	  BigInteger yOut = s.getAffineY().negate().mod(prime);
    	  yOut = yOut.add(slope.multiply(s.getAffineX().subtract(xOut))).mod(prime);
    	  ECPoint out = new ECPoint(xOut, yOut);
    	  return out;
    	}
//    public BigInteger nextRandomBigInteger(BigInteger n) {
//        Random rand = new Random();
//        BigInteger result = new BigInteger(n.bitLength(), rand);
//        while( result.compareTo(n) >= 0 ) {
//            result = new BigInteger(n.bitLength(), rand);
//        }
//        return result;
//    }
    public static ECPoint scalmult(ECPoint P, BigInteger kin,EllipticCurve curve){
        //ECPoint R=P; - incorrect
        ECPoint R = ECPoint.POINT_INFINITY,S = P;
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger k = kin.mod(p);
        int length = k.bitLength();
        //System.out.println("length is" + length);
        byte[] binarray = new byte[length];
        for(int i=0;i<=length-1;i++){
            binarray[i] = k.mod(TWO).byteValue ();
            k = k.divide(TWO);
        }
        /*for(int i = length-1;i >= 0;i--){
            System.out.print("" + binarray[i]); 
        }*/

        for(int i = length-1;i >= 0;i--){
            // i should start at length-1 not -2 because the MSB of binarry may not be 1
            R = doublePoint(R,curve);
            if(binarray[i]== 1) 
                R = addPoint(R, S,curve);
        }
    return R;
    }
	
	

}
