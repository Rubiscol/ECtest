package test;

import java.math.BigInteger;
import java.util.ArrayList;
import org.javatuples.Triplet;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javafx.util.Pair;

public class DKeyGen {
	private ArrayList<Pair<BigInteger, BigInteger>> msk;
	private ArrayList<BigInteger> w;
	private Triplet<ArrayList<BigInteger>,ECPoint,ECPoint> fpk;
	private BigInteger p;
	BigInteger ws_1=BigInteger.ZERO;
	BigInteger ws_2=BigInteger.ZERO;
	public DKeyGen(ArrayList<Pair<BigInteger, BigInteger>> msk,ArrayList<BigInteger> w,BigInteger p) {
		this.msk=msk;
		this.w=w;
		this.p=p;
		
		// TODO Auto-generated constructor stub
	}
	public Pair<BigInteger, BigInteger> getfsk(){
		ws_1=BigInteger.ZERO;
		ws_2=BigInteger.ZERO;
		for(int i=0;i<w.size();i++) {
			ws_1=(ws_1.add(w.get(i).multiply(msk.get(i).getKey()))).mod(p);
			ws_2=(ws_2.add(w.get(i).multiply(msk.get(i).getValue()))).mod(p);			
		}
		System.out.println("fsk is");
		System.out.println(ws_1);
		System.out.println(ws_2);
		return new Pair<BigInteger, BigInteger>(ws_1, ws_2);
		
	}
	public Triplet<ArrayList<BigInteger>,ECPoint,ECPoint> getfpk(ECPoint G,EllipticCurve curve) {
		getfsk();
	
		fpk=new Triplet<ArrayList<BigInteger>, ECPoint, ECPoint>(w,ECPointCalculator.scalmult(G, ws_1, curve),ECPointCalculator.scalmult(G, ws_2, curve));
		return fpk;
		
	}

}
