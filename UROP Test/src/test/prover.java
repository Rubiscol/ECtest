package test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.javatuples.Triplet;

public class prover {
//	EllipticCurve G;
//	ECPoint g, h, gy, hy;
//	BigInteger y;
//	public prover(EllipticCurve G, ECPoint g,ECPoint h,ECPoint gy, ECPoint hy,BigInteger y) {
//		this.G=G;
//		this.g=g;
//		this.h=h;
//		this.gy=gy;
//		this.hy=hy;
//		this.y=y;
//	}
	
	public static Triplet<ECPoint,ECPoint,BigInteger> proverTest(EllipticCurve G, ECPoint g,ECPoint h,ECPoint gy, ECPoint hy,BigInteger y) throws NoSuchAlgorithmException {
		System.out.println("============");
		System.out.println("Prover");
    	BigInteger u=testUROP.nextRandomBigInteger(testUROP.securityParameter);
    	
    	ECPoint gu=ECPointCalculator.scalmult(g, u, G);
    	ECPoint hu=ECPointCalculator.scalmult(h, u, G);
    	
    	ECPoint hashPoint=ECPointCalculator.addPoint(g, h, G);
    	hashPoint=ECPointCalculator.addPoint(hashPoint,gu, G);
    	hashPoint=ECPointCalculator.addPoint(hashPoint,hu, G);
    	hashPoint=ECPointCalculator.addPoint(gy, hashPoint, G);
    	hashPoint=ECPointCalculator.addPoint(hy, hashPoint, G);
    	// I don't know 
    	BigInteger c=SHA256Calculator.doSHA256(hashPoint.hashCode());

    	
    	BigInteger z=u.add(c.multiply(y));
    	Triplet<ECPoint,ECPoint,BigInteger> H=new Triplet<>(gu, hu, z);
    	
    	System.out.println("z"+H.getValue2());
    	System.out.println("ug"+H.getValue0().getAffineX());
    	System.out.println("uh"+H.getValue1().getAffineX());
    	return H;

    }

}
