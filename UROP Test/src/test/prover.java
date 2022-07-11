package test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.javatuples.Triplet;

public class prover {
	

	
	public static Triplet<ECPoint,ECPoint,BigInteger> proverTest(ECCurve G, ECPoint g,ECPoint h,ECPoint gy, ECPoint hy,BigInteger y) throws NoSuchAlgorithmException {
		System.out.println("============");
		System.out.println("Prover");
    	BigInteger u=testUROP.nextRandomBigInteger(testUROP.securityParameter);
    	System.out.println("Prover u "+u);
    	ECPoint gu=g.multiply(u).normalize();
    	System.out.println("Prover gu "+gu.getAffineXCoord());
    	ECPoint hu=h.multiply(u).normalize();
    	System.out.println("Prover hu "+hu.getAffineXCoord());
    	ECPoint hashPoint=g.add(h);
    	hashPoint=hashPoint.add(gu);
    	hashPoint=hashPoint.add(hu);
    	hashPoint=hashPoint.add(gy);
    	hashPoint=hashPoint.add(hy);
    	BigInteger c=SHA256Calculator.doSHA256(hashPoint.hashCode());
    	System.out.println("Prover c "+c);
    	
    	BigInteger z=u.add(c.multiply(y));
    	System.out.println("Prover z "+z);
    	Triplet<ECPoint,ECPoint,BigInteger> H=new Triplet<>(gu, hu, z);
//    	
//    	System.out.println("z"+H.getValue2());
//    	System.out.println("ug"+H.getValue0().getAffineX());
//    	System.out.println("uh"+H.getValue1().getAffineX());
    	return H;

    }

}
