package test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import javafx.util.Pair;

public class Encryption {
	private BigInteger originalmessage;
	private BigInteger label;
	private Pair<ECPoint, ECPoint> ut;
	private Pair<BigInteger, BigInteger> encryptionkey;
	private ECPoint G;
	private ECCurve curve;
	
	public Encryption(BigInteger x, BigInteger label, BigInteger s_1, BigInteger s_2,ECPoint G,ECCurve curve) {
		originalmessage = x;
		this.label = label;
		encryptionkey = new Pair<BigInteger, BigInteger>(s_1, s_2);
		this.G=G;
		this.curve=curve;
		
		
	}
	public Pair<ECPoint, ECPoint> getut() throws NoSuchAlgorithmException {
		
		BigInteger h1=SHA256Calculator.doSHA256(label);
		BigInteger h2=SHA256Calculator.doSHA256(h1);
		ut=new Pair<ECPoint, ECPoint>(G.multiply(h1).normalize(), G.multiply(h2).normalize());
		return ut;
	}
	
	public ECPoint getCipherText() throws NoSuchAlgorithmException {
		
		
		ut=getut();
		ECPoint p1=ut.getKey().multiply(encryptionkey.getKey()).normalize();
		ECPoint p2=ut.getValue().multiply(encryptionkey.getValue()).normalize();
		ECPoint p3=G.multiply(originalmessage).normalize();
		ECPoint p4=p2.add(p3);
		ECPoint finalEcPoint=p1.add(p4);
		return finalEcPoint.normalize();
	}
	
	
    

}
