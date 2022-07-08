package test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import javafx.util.Pair;

public class Encryption {
	private BigInteger originalmessage;
	private BigInteger label;
	private Pair<ECPoint, ECPoint> ut;
	private Pair<BigInteger, BigInteger> encryptionkey;
	private ECPoint G;
	private EllipticCurve curve;
	
	public Encryption(BigInteger x, BigInteger label, BigInteger s_1, BigInteger s_2,ECPoint G,EllipticCurve curve) {
		originalmessage = x;
		this.label = label;
		encryptionkey = new Pair<BigInteger, BigInteger>(s_1, s_2);
		this.G=G;
		this.curve=curve;
		
		
	}
	public Pair<ECPoint, ECPoint> getut() throws NoSuchAlgorithmException {
		
//		BigInteger h1=testUROP.nextRandomBigInteger(testUROP.securityParameter);
		BigInteger h1=SHA256Calculator.doSHA256(label);
		BigInteger h2=SHA256Calculator.doSHA256(h1);
		ut=new Pair<ECPoint, ECPoint>(ECPointCalculator.scalmult(G,h1, curve), ECPointCalculator.scalmult(G,h2, curve));
		return ut;
	}
	
	public ECPoint getCipherText() throws NoSuchAlgorithmException {
		
		
		ut=getut();
		ECPoint p1=ECPointCalculator.scalmult(ut.getKey(),encryptionkey.getKey(),curve);
		ECPoint p2=ECPointCalculator.scalmult(ut.getValue(),encryptionkey.getValue(),curve);
		ECPoint p3=ECPointCalculator.scalmult(G,originalmessage,curve);
		ECPoint p4=ECPointCalculator.addPoint(p2, p3, curve);
		ECPoint finalEcPoint=ECPointCalculator.addPoint(p1, p4, curve);
		return finalEcPoint;
	}
	
	
    

}
