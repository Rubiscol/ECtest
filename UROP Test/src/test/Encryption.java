package test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.HashMap;

import org.bouncycastle.util.encoders.Hex;

import javafx.util.Pair;
import net.i2p.util.NativeBigInteger;

public class Encryption {
	private BigInteger originalmessage;
	private BigInteger label;
	private Pair<BigInteger, BigInteger> encryptionkey;
	public Encryption(BigInteger x, BigInteger label, BigInteger s_1, BigInteger s_2) {
		originalmessage = x;
		this.label = label;
		encryptionkey = new Pair<BigInteger, BigInteger>(s_1, s_2);
		
	}

	public ECPoint getCipherText(ECPoint G,EllipticCurve curve) throws NoSuchAlgorithmException {
		BigInteger h1=doSHA256(label);
		BigInteger h2=doSHA256(h1);
		ECPointCalculator ecPointCalculator=new ECPointCalculator();
		ECPoint p1=ecPointCalculator.scalmult(ecPointCalculator.scalmult(G,h1, curve),encryptionkey.getKey(),curve);
		ECPoint p2=ecPointCalculator.scalmult(ecPointCalculator.scalmult(G,h2, curve),encryptionkey.getValue(),curve);
		ECPoint p3=ecPointCalculator.scalmult(G,originalmessage,curve);
		ECPoint p4=ecPointCalculator.addPoint(p2, p3, curve);
		ECPoint finalEcPoint=ecPointCalculator.addPoint(p1, p4, curve);
		return finalEcPoint;
	}

	
	public BigInteger doSHA256(BigInteger t) throws NoSuchAlgorithmException {
		// Here I directly hash the string of the bigInteger and may cause problems
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(t.toString().getBytes(StandardCharsets.UTF_8));
		return new BigInteger(hash);
	}
    

}
