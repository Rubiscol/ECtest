package test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
//import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.time.Year;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.javatuples.Triplet;
import org.javatuples.Tuple;

import javafx.util.Pair;

public class EQprotocol {
	ECPoint w;
	Pair<BigInteger, BigInteger> fsk;
	BigInteger a;
	Pair<ECPoint, ECPoint> utEcPoint;
	static ECCurve curve;
	public static BigInteger y;
	
	public EQprotocol(ECPoint ecPoint, Pair<BigInteger, BigInteger> fsk, BigInteger a, Pair<ECPoint, ECPoint> utEcPoint,
			ECCurve curve) {
		this.w=ecPoint;
		this.fsk=fsk;
		this.a=a;
		this.utEcPoint=utEcPoint;
		this.curve=curve;
		// TODO Auto-generated constructor stub
	}

    public static boolean unitedTest(ECCurve G, ECPoint g,ECPoint h,BigInteger y) throws NoSuchAlgorithmException {
    	ECPoint gy=g.multiply(y).normalize();
    	ECPoint hy=h.multiply(y).normalize();
   
    	Triplet<ECPoint,ECPoint,BigInteger> triplet=prover.proverTest(G, g, h, gy,  hy, y) ;
    	return verifier.verifierTest(G, g, h, gy,  hy,triplet);
    	
    	
    }
    public static void main(String[] args) throws NoSuchAlgorithmException  {
//    	BigInteger prime = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041");
//        BigInteger A = new BigInteger("7");
//        BigInteger B = new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414");
//
//        ECCurve curve = new ECCurve.Fp(prime, A, B);
//
//        BigInteger Px = new BigInteger("2");
//        BigInteger Py = new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280");
//        BigInteger Qx = new BigInteger("57520216126176808443631405023338071176630104906313632182896741342206604859403");
//        BigInteger Qy = new BigInteger("17614944419213781543809391949654080031942662045363639260709847859438286763994");
//
//        // Explicit affine addition
//        ECFieldElement xp = curve.fromBigInteger(Px), yp = curve.fromBigInteger(Py);
//        ECFieldElement xq = curve.fromBigInteger(Qx), yq = curve.fromBigInteger(Qy);
//        ECFieldElement alpha = yq.subtract(yp).divide(xq.subtract(xp));
//        ECFieldElement xr = alpha.square().subtract(xp).subtract(xq);
//        ECFieldElement yr = xp.subtract(xr).multiply(alpha).subtract(yp);
//
//        System.out.println("EXPLICIT");
//        System.out.println(xr.toBigInteger().toString(10));
//        System.out.println(yr.toBigInteger().toString(10));
//
//        // Point addition using built-in formulae
//        ECPoint Q = curve.createPoint(Px, Py);
//        ECPoint g = curve.createPoint(Qx, Qy);
//       
//    	BigInteger y=testUROP.nextRandomBigInteger(testUROP.securityParameter);
//    	System.out.println("y "+y);
//    	BigInteger u=testUROP.nextRandomBigInteger(testUROP.securityParameter);
//    	System.out.println("u "+u);
//    	BigInteger c=testUROP.nextRandomBigInteger(testUROP.securityParameter);
//    	System.out.println("c "+c);
//    	BigInteger z=u.add(c.multiply(y));
//    	System.out.println("z "+z);
//    	
//    	ECPoint zg=g.multiply(z).normalize();
//    	ECPoint ug=g.multiply(u);
//    	ECPoint yg=g.multiply(y);
//    	BigInteger cy=y.multiply(c);
//    	ECPoint cyg=g.multiply(cy);
//    	ECPoint ugcyg=ug.add(cyg).normalize();
//    	System.out.println("Whether z*g=u*g+(c*y)*g: "+zg.equals(ugcyg));
//    	cyg=yg.multiply(c);
//    	ugcyg=ug.add(cyg).normalize();
//    	System.out.println("Whether z*g=u*g+c*(y*g): "+zg.equals(ugcyg));
//    	System.out.println(" ");
    	
    	
    	
    	
    	
//    	for(int i=0;i<10;i++) {
//    	ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
//		ECPoint g=spec.getG();
//		ECCurve G=g.getCurve();
//		y=testUROP.nextRandomBigInteger(testUROP.securityParameter);
//		System.out.println("The scalar parameter is "+ y);
//		ECPoint h=g.multiply(y);
//		unitedTest(G, g, h, y);
        
//    	for (int i=0;i<100;i++) {
//    	KeyPair k1=testUROP.generateRandom();
//    	ECPublicKey publickey=(ECPublicKey)k1.getPublic();
//		ECPrivateKey privatekey=(ECPrivateKey)k1.getPrivate();
//		EllipticCurve G =privatekey.getParams().getCurve();
//		ECPoint g=publickey.getW();
////    	System.out.println("g x "+g.getAffineX());
////    	System.out.println("g y "+g.getAffineY());
//    	ECPoint h=ECPointCalculator.scalmult(g, BigInteger.valueOf(3), G);
////    	System.out.println("h x "+h.getAffineX());
////    	System.out.println("h y "+h.getAffineY());
//    	
//    	BigInteger y=testUROP.nextRandomBigInteger(testUROP.securityParameter);
////    	System.out.println("y "+y);
//    	BigInteger u=testUROP.nextRandomBigInteger(testUROP.securityParameter);
////    	System.out.println("u "+u);
//    	BigInteger c=testUROP.nextRandomBigInteger(testUROP.securityParameter);
////    	System.out.println("c "+c);
//    	
//    	
//    	BigInteger z=u.add(c.multiply(y));
////    	System.out.println("z "+z);
////    	System.out.println("result :"+unitedTest(G,g,h,y));
//    	
//    	ECPoint zg=ECPointCalculator.scalmult(g, z, G);
//    	ECPoint ug=ECPointCalculator.scalmult(g, u, G);
//    	ECPoint yg=ECPointCalculator.scalmult(g, y, G);
//    	BigInteger cy=y.multiply(c);
//    	ECPoint cyg=ECPointCalculator.scalmult(g, cy,G);
//    	ECPoint ugcyg=ECPointCalculator.addPoint(ug, cyg, G);
//    	System.out.println("Whether z*g=u*g+(c*y)*g: "+zg.equals(ugcyg));
//    	cyg=ECPointCalculator.scalmult(yg, c,G);
//    	ugcyg=ECPointCalculator.addPoint(ug, cyg, G);
//    	System.out.println("Whether z*g=u*g+c*(y*g): "+zg.equals(ugcyg));
//    	System.out.println(" ");
//    	
//    	
////    	z=c.multiply(y);
////    	zg=ECPointCalculator.scalmult(g, z, G);
////    	ECPoint cy=ECPointCalculator.scalmult(g, c.multiply(y), G);
////    	System.out.println(zg.equals(cy));
//    	
//    	}	
    	
    }
    public boolean NIZKtest() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    	
    	
    	//gfsk(1)
    	ECPoint p1=w.multiply(fsk.getKey());
    	//ga
    	ECPoint p2=w.multiply(a);
    	//gafsk(1)
    	ECPoint p3=p1.multiply(a);
    	//ut1afsk(1)
    	ECPoint p4=utEcPoint.getKey().multiply(a);
    	p4=p4.multiply(fsk.getKey());
    	//gfsk(2)
    	ECPoint p5=w.multiply(fsk.getValue());
    	//gfsk(2)a
    	ECPoint p6=p5.multiply(a);
    	//ut2afsk(2)
    	ECPoint p7=utEcPoint.getValue().multiply(a);
    	p7=p7.multiply(fsk.getValue());
    	
    	Boolean boolean1=unitedTest(curve,w,p2,fsk.getKey());
    	Boolean boolean2=unitedTest(curve,w,utEcPoint.getKey(),fsk.getKey().multiply(a));
    	Boolean boolean3=unitedTest(curve, w, p2,fsk.getValue());
    	Boolean boolean4=unitedTest(curve, w, utEcPoint.getValue(), fsk.getValue().multiply(a));
    	
    	
    	
    	return  boolean1&&
    			boolean2&&
    			boolean3&&
    			boolean4;
    	
    }
	
	
	
	

}
