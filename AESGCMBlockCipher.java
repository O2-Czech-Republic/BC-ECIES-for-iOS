package cz.o2.smartbox.utility.security;

import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.GCMBlockCipher;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.NoSuchPaddingException;


public class AESGCMBlockCipher extends BufferedBlockCipher {

	private GCMBlockCipher internalCipher;


	public AESGCMBlockCipher()
			throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		this.internalCipher = new GCMBlockCipher(new AESEngine());
	}


	@Override
	public void init(boolean forEncryption, CipherParameters params) {
		internalCipher.init(forEncryption, params);
	}


	@Override
	public int getOutputSize(int len) {
		return internalCipher.getOutputSize(len);
	}


	@Override
	public int doFinal(byte[] out, int outOff) throws InvalidCipherTextException {
		return internalCipher.doFinal(out, outOff);
	}


	@Override
	public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) {
		return internalCipher.processBytes(in, inOff, len, out, outOff);
	}
}