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
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

import org.bouncycastle.util.encoders.Hex;
import org.javatuples.Triplet;
import org.minidns.record.AAAA;

import javafx.util.Pair;
import net.i2p.util.NativeBigInteger;

public class testUROP {
	public final static BigInteger TWO = BigInteger.valueOf(2); // constant for scalar operations
	public final static BigInteger THREE = BigInteger.valueOf(3);
	public static Integer securityParameter=1000;
	public static ArrayList<Pair<BigInteger, BigInteger>> msk;
	public static Pair<BigInteger, BigInteger> fsk;
	public static ArrayList<BigInteger> w;
	public static Pair<ECPoint, ECPoint> utEcPoint;
	public static ECPublicKey PublicKey;
	public static ECPrivateKey PrivateKey;
	
	
		
//	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException  {
//		
//		Setup();
//		testDKeyGen();
//		testEncrypt();
//		
//		testNIZP();
//		
//		
//	}
	private static void testNIZP() throws NoSuchAlgorithmException {
		System.out.println("---------------------------------------");
		System.out.println("Test Zero Knowledge provement");
		System.out.println("---------------------------------------");
		BigInteger a=nextRandomBigInteger(securityParameter);
		System.out.println("Hi broker, your random a is "+a);
		EllipticCurve curve =PrivateKey.getParams().getCurve();
		EQprotocol protocol =new EQprotocol(PublicKey.getW(),fsk,a,utEcPoint,curve);
		if(protocol.NIZKtest()) {
			System.out.println("Pass the four tests");
		}
		else {
			System.out.println("Fail to verify");
		}
		// TODO Auto-generated method stub
		
	}
	private static void testDKeyGen() {
		System.out.println("---------------------------------------");
		System.out.println("DKeyGen");
		System.out.println("---------------------------------------");
		System.out.println("DKeyGen(msk, w):");
		
		System.out.println("msk=");
		msk.forEach(s->{
			System.out.println("s1: "+s.getKey());
			System.out.println("s2: "+s.getValue());
		});
		DKeyGen dKeyGen=new DKeyGen(msk, w, TWO.pow(securityParameter));
		Triplet<ArrayList<BigInteger>,ECPoint,ECPoint> fpkTriplet=
				dKeyGen.getfpk(PublicKey.getW(), PrivateKey.getParams().getCurve());
		System.out.println("The w of fpk is: ");
		System.out.println("vector of weights w=");
		for(int i=0;i<w.size();i++) {
			System.out.println("w"+i+": "+w.get(i).toString());
		}
		fsk=dKeyGen.getfsk();
		System.out.println("The first point of fpk is: ");
		System.out.println("The x coordinate :"+fpkTriplet.getValue1().getAffineX());
		System.out.println("The y coordinate :"+fpkTriplet.getValue1().getAffineY());
		System.out.println("The second point of fpk is: ");
		System.out.println("The x coordinate :"+fpkTriplet.getValue2().getAffineX());
		System.out.println("The y coordinate :"+fpkTriplet.getValue2().getAffineY());
		// TODO Auto-generated method stub
		
	}
	private static void Setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		System.out.println("---------------------------------------");
		System.out.println("Setup");
		System.out.println("---------------------------------------");
		System.out.print("Please specify your the security parameter: ");
		Scanner scanner = new Scanner(System.in);
		msk=new ArrayList<>();
		w=new ArrayList<>();
		securityParameter =scanner.nextInt();
		System.out.print("Please specify your the number of ciphertexts n: ");
		Scanner nscanner = new Scanner(System.in);
		int n =nscanner.nextInt();
		scanner.close();
		nscanner.close();
		for(int i=0;i<n;i++) {
			BigInteger s_1=nextRandomBigInteger(securityParameter);
			BigInteger s_2=nextRandomBigInteger(securityParameter);
			Pair<BigInteger, BigInteger> s=new Pair<>(s_1,s_2);
			msk.add(s);
			w.add(nextRandomBigInteger(securityParameter));
		}
		KeyPair k1=generateRandom();
		PublicKey=(ECPublicKey)k1.getPublic();
		PrivateKey=(ECPrivateKey)k1.getPrivate();
		
	}
	private static void testEncrypt() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
	
		System.out.println("---------------------------------------");
		System.out.println("Encrypt");
		System.out.println("---------------------------------------");
		EllipticCurve curve =PrivateKey.getParams().getCurve();
		System.out.println("The generators's KeyPair: ");
		System.out.println(PublicKey); 
		System.out.println("Private Key is: "+getPrivateKeyAsHex(PrivateKey));
		BigInteger messageBigInteger=nextRandomBigInteger(40);
		System.out.println("The raw message is: "+messageBigInteger);
		BigInteger label=nextRandomBigInteger(securityParameter);
		System.out.println("The label is: "+label);
		ECPoint p1=PublicKey.getW();
		System.out.println("---------------------------------------");
		for(int i=0;i<w.size();i++) {
			Encryption tEncryption=new Encryption(messageBigInteger,label,msk.get(i).getKey(),msk.get(i).getValue(),p1, curve);
			ECPoint point=tEncryption.getCipherText();
			System.out.println("The x coordinate of cipherText "+(i+1)+" is: "+point.getAffineX());
			System.out.println("The y coordinate of cipherText "+(i+1)+" is: "+point.getAffineY());
			System.out.println("");
			utEcPoint=tEncryption.getut();
			
		}
		
		
		
	}
	public static BigInteger nextRandomBigInteger(Integer securityParameter) {
		BigInteger n=TWO.pow(securityParameter);
	    Random rand = new Random();
	    BigInteger result = new BigInteger(n.bitLength(), rand);
	    while( result.compareTo(n) >= 0 ) {
	        result = new BigInteger(n.bitLength(), rand);
	    }
	    return result;
	}
	public static KeyPair generateRandom() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
		keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	public static ECPoint generateRandomECPoint() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
		keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey=(ECPublicKey)keyPair.getPublic();
		ECPoint p1=PublicKey.getW();
		return p1;
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

}
