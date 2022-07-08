package test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.javatuples.Triplet;

public class verifier {
	
	 public static boolean verifierTest(EllipticCurve G, ECPoint g,ECPoint h,ECPoint gy, ECPoint hy,Triplet<ECPoint,ECPoint,BigInteger>H) throws NoSuchAlgorithmException {
		    System.out.println("============");
	    	System.out.println("Verifier");
	    	System.out.println("z"+H.getValue2());
	    	System.out.println("ug"+H.getValue0().getAffineX());
	    	System.out.println("uh"+H.getValue1().getAffineX());
	    	ECPoint hashPoint=ECPointCalculator.addPoint(g, h, G);
	    	hashPoint=ECPointCalculator.addPoint(hashPoint,H.getValue0(), G);
	    	hashPoint=ECPointCalculator.addPoint(hashPoint, H.getValue1(), G);
	    	hashPoint=ECPointCalculator.addPoint(gy, hashPoint, G);
	    	hashPoint=ECPointCalculator.addPoint(hy, hashPoint, G);
	    	// I don't know 
	    	BigInteger c=SHA256Calculator.doSHA256(hashPoint.hashCode());
	    	System.out.println("In verifier c= "+c);
	    	ECPoint left0=ECPointCalculator.scalmult(g, H.getValue2(), G);
	    	ECPoint right0=ECPointCalculator.scalmult(gy, c, G);
	    	
	    	right0=ECPointCalculator.addPoint(right0, H.getValue0(), G);
	    	
	    	ECPoint left1=ECPointCalculator.scalmult(h, H.getValue2(), G);
	    	ECPoint right1=ECPointCalculator.scalmult(hy, c, G);
	    	
	    	right1=ECPointCalculator.addPoint(right1, H.getValue1(), G);
	    	System.out.println("left0=");
	    	System.out.println(left0.getAffineX());
	    	System.out.println("righ0=");
	    	System.out.println(right0.getAffineX());
	    	if(left0.equals(right0)&&left1.equals(right1)) {
	    		return true;
	    	}
	    	else {
	    		return false;
	    	}
	    	
	    }

}
