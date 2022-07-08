package test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.time.Year;

import org.javatuples.Triplet;
import org.javatuples.Tuple;

import javafx.util.Pair;

public class EQprotocol {
	ECPoint w;
	Pair<BigInteger, BigInteger> fsk;
	BigInteger a;
	Pair<ECPoint, ECPoint> utEcPoint;
	static EllipticCurve curve;
	
	
	public EQprotocol(ECPoint w, Pair<BigInteger, BigInteger> fsk, BigInteger a, Pair<ECPoint, ECPoint> utEcPoint,
			EllipticCurve curve) {
		this.w=w;
		this.fsk=fsk;
		this.a=a;
		this.utEcPoint=utEcPoint;
		this.curve=curve;
		// TODO Auto-generated constructor stub
	}

    public static boolean unitedTest(EllipticCurve G, ECPoint g,ECPoint h,BigInteger y) throws NoSuchAlgorithmException {
    	ECPoint gy=ECPointCalculator.scalmult(g, y, G);
    	ECPoint hy=ECPointCalculator.scalmult(h, y, G);
  
    	Triplet<ECPoint,ECPoint,BigInteger> triplet=prover.proverTest(G, g, h, gy,  hy, y) ;
    	return verifier.verifierTest(G, g, h, gy,  hy,triplet);
    	
    	
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    	for (int i=0;i<100;i++) {
    	KeyPair k1=testUROP.generateRandom();
    	ECPublicKey publickey=(ECPublicKey)k1.getPublic();
		ECPrivateKey privatekey=(ECPrivateKey)k1.getPrivate();
		EllipticCurve G =privatekey.getParams().getCurve();
		ECPoint g=publickey.getW();
//    	System.out.println("g x "+g.getAffineX());
//    	System.out.println("g y "+g.getAffineY());
    	ECPoint h=ECPointCalculator.scalmult(g, BigInteger.valueOf(3), G);
//    	System.out.println("h x "+h.getAffineX());
//    	System.out.println("h y "+h.getAffineY());
    	
    	BigInteger y=testUROP.nextRandomBigInteger(testUROP.securityParameter);
//    	System.out.println("y "+y);
    	BigInteger u=testUROP.nextRandomBigInteger(testUROP.securityParameter);
//    	System.out.println("u "+u);
    	BigInteger c=testUROP.nextRandomBigInteger(testUROP.securityParameter);
//    	System.out.println("c "+c);
    	
    	
    	BigInteger z=u.add(c.multiply(y));
//    	System.out.println("z "+z);
//    	System.out.println("result :"+unitedTest(G,g,h,y));
    	
    	ECPoint zg=ECPointCalculator.scalmult(g, z, G);
    	ECPoint ug=ECPointCalculator.scalmult(g, u, G);
    	ECPoint yg=ECPointCalculator.scalmult(g, y, G);
    	BigInteger cy=y.multiply(c);
    	ECPoint cyg=ECPointCalculator.scalmult(g, cy,G);
    	ECPoint ugcyg=ECPointCalculator.addPoint(ug, cyg, G);
    	System.out.println("Whether z*g=u*g+(c*y)*g: "+zg.equals(ugcyg));
    	cyg=ECPointCalculator.scalmult(yg, c,G);
    	ugcyg=ECPointCalculator.addPoint(ug, cyg, G);
    	System.out.println("Whether z*g=u*g+c*(y*g): "+zg.equals(ugcyg));
    	System.out.println(" ");
    	
    	
//    	z=c.multiply(y);
//    	zg=ECPointCalculator.scalmult(g, z, G);
//    	ECPoint cy=ECPointCalculator.scalmult(g, c.multiply(y), G);
//    	System.out.println(zg.equals(cy));
    	
    	}	
    	
    }
    public boolean NIZKtest() throws NoSuchAlgorithmException {
    	
    	//gfsk(1)
    	ECPoint p1=ECPointCalculator.scalmult(w, fsk.getKey(), curve);
    	//ga
    	ECPoint p2=ECPointCalculator.scalmult(w, a, curve);
    	//gafsk(1)
    	ECPoint p3=ECPointCalculator.scalmult(p1, a, curve);
    	//ut1afsk(1)
    	ECPoint p4=ECPointCalculator.scalmult(utEcPoint.getKey(), a, curve);
    	p4=ECPointCalculator.scalmult(p4, fsk.getKey(), curve);
    	//gfsk(2)
    	ECPoint p5=ECPointCalculator.scalmult(w, fsk.getValue(), curve);
    	//gfsk(2)a
    	ECPoint p6=ECPointCalculator.scalmult(p5, a, curve);
    	//ut2afsk(2)
    	ECPoint p7=ECPointCalculator.scalmult(utEcPoint.getValue(), a, curve);
    	p7=ECPointCalculator.scalmult(p7, fsk.getValue(), curve);
    	
    	System.out.println(unitedTest(curve,w,p2,fsk.getKey()));
    	System.out.println(unitedTest(curve,w,utEcPoint.getKey(),fsk.getKey().multiply(a)));
    	System.out.println(unitedTest(curve, w, p2,fsk.getValue()));
    	System.out.println(unitedTest(curve, w, utEcPoint.getValue(), fsk.getValue().multiply(a)));
    	
    	
    	return  unitedTest(curve,w,p2,fsk.getKey())&&
    			unitedTest(curve,w,utEcPoint.getKey(),fsk.getKey().multiply(a))&&
    			unitedTest(curve, w, p2,fsk.getValue())&&
    			unitedTest(curve, w, utEcPoint.getValue(), fsk.getValue().multiply(a));
    	
    }
	
	
	
	

}
