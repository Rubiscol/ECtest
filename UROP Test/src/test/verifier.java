package test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import org.javatuples.Triplet;

public class verifier {
	
	 public static boolean verifierTest(ECCurve G, ECPoint g,ECPoint h,ECPoint yg, ECPoint yh,Triplet<ECPoint,ECPoint,BigInteger>H) throws NoSuchAlgorithmException {
		    System.out.println("============");
	    	System.out.println("Verifier");
	    	
	    	BigInteger z=H.getValue2();
	    	ECPoint ug=H.getValue0();
	    	ECPoint uh=H.getValue1();
	    	System.out.println("Verifier z "+z);
	    	System.out.println("Verifier ug "+ug.getAffineXCoord());
	    	System.out.println("Verifier uh "+uh.getAffineXCoord());
	    	
	    	ECPoint hashPoint=g.add(h);
	    	hashPoint=hashPoint.add(ug).normalize();
	    	hashPoint=hashPoint.add(uh).normalize();
	    	hashPoint=hashPoint.add(yg).normalize();
	    	hashPoint=hashPoint.add(yh).normalize();
	    	BigInteger c=SHA256Calculator.doSHA256(hashPoint.hashCode());
	    	System.out.println("Prover c "+c);
	    	
	    	ECPoint zg=g.multiply(z).normalize();
	    	System.out.println("Verifier zg "+zg.getAffineXCoord());

	    	ECPoint cgy=yg.multiply(c).normalize();
	    	System.out.println("Verifier cyg "+cgy.getAffineXCoord());
	 	    ECPoint ugcgy=cgy.add(ug).normalize();
	 	    System.out.println("Verifier ugcyg "+ugcgy.getAffineXCoord());
	    	ECPoint zh=h.multiply(z).normalize();
	    	ECPoint chy=yh.multiply(c).normalize();
	    	
	    	ECPoint uhchy=chy.add(uh).normalize();
	    	System.out.println(zg.equals(ugcgy));
	    	if(zg.equals(ugcgy)&& zh.equals(uhchy)) {	
	    		return true;
	    	}
	    	else {
	    		return false;
	    	}
	    	
	    }

}
