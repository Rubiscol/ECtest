//package test;
//
//import java.math.BigInteger;
//import java.security.spec.ECFieldFp;
//import java.security.spec.ECPoint;
//import java.security.spec.EllipticCurve;
//
//import net.i2p.util.NativeBigInteger;
//
//public class ECPointCalculator {
//	public final static BigInteger TWO = BigInteger.valueOf(2); 
//	public final static BigInteger THREE = BigInteger.valueOf(3);
//
//
//private static ECPoint doublePoint(ECPoint r, EllipticCurve curve) {
//	  if (r.equals(ECPoint.POINT_INFINITY)) 
//	    return r;
//	  BigInteger slope = (r.getAffineX().pow(2)).multiply(THREE);
//	  slope = slope.add(curve.getA());
//	  BigInteger prime = ((ECFieldFp) curve.getField()).getP();
//	  // use NBI modInverse();
//	  BigInteger tmp = r.getAffineY().multiply(TWO);
//	  tmp = new NativeBigInteger(tmp);
//	  slope = slope.multiply(tmp.modInverse(prime));
//	  BigInteger xOut = slope.pow(2).subtract(r.getAffineX().multiply(TWO)).mod(prime);
//	  BigInteger yOut = (r.getAffineY().negate()).add(slope.multiply(r.getAffineX().subtract(xOut))).mod(prime);
//	  ECPoint out = new ECPoint(xOut, yOut);
//	  return out;
//	}
//public  static ECPoint addPoint(ECPoint r, ECPoint s, EllipticCurve curve) {
//	  if (r.equals(s))
//	    return doublePoint(r, curve);
//	  else if (r.equals(ECPoint.POINT_INFINITY))
//	    return s;
//	  else if (s.equals(ECPoint.POINT_INFINITY))
//	    return r;
//	  BigInteger prime = ((ECFieldFp)curve.getField()).getP();
//	  // use NBI modInverse();
//	  BigInteger tmp = r.getAffineX().subtract(s.getAffineX());
//	  tmp = new NativeBigInteger(tmp);
//	  BigInteger slope = (r.getAffineY().subtract(s.getAffineY())).multiply(tmp.modInverse(prime)).mod(prime);
//	  slope = new NativeBigInteger(slope);
//	  BigInteger xOut = (slope.modPow(TWO, prime).subtract(r.getAffineX())).subtract(s.getAffineX()).mod(prime);
//	  BigInteger yOut = s.getAffineY().negate().mod(prime);
//	  yOut = yOut.add(slope.multiply(s.getAffineX().subtract(xOut))).mod(prime);
//	  ECPoint out = new ECPoint(xOut, yOut);
//	  return out;
//	}
//
//public static ECPoint scalmult(ECPoint P, BigInteger kin,EllipticCurve curve){
//    //ECPoint R=P; - incorrect
//    ECPoint R = ECPoint.POINT_INFINITY,S = P;
//    BigInteger p = ((ECFieldFp) curve.getField()).getP();
//    BigInteger k = kin.mod(p);
//    int length = k.bitLength();
//    //System.out.println("length is" + length);
//    byte[] binarray = new byte[length];
//    for(int i=0;i<=length-1;i++){
//        binarray[i] = k.mod(TWO).byteValue ();
//        k = k.divide(TWO);
//    }
// 
//    for(int i = length-1;i >= 0;i--){
//        // i should start at length-1 not -2 because the MSB of binarry may not be 1
//        R = doublePoint(R,curve);
//        if(binarray[i]== 1) 
//            R = addPoint(R, S,curve);
//    }
//return R;
//}
//}
//	
