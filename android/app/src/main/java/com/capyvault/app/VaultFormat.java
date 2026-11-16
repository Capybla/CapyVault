package com.capyvault.app;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Android implementation of docs/vault-format-v1.md; only format primitives live here. */
public final class VaultFormat {
    private static final byte[] MAGIC = new byte[]{'C','A','P','Y','V','L','T',0};
    private static final int CORE = 111, HEADER = 207, TAG = 16, DEK = 32;
    private static final long MAX_FILE = 4L * 1024 * 1024 * 1024 - 1;
    private static final SecureRandom RNG = new SecureRandom();

    private VaultFormat() {}

    public static final class Created {
        public final byte[] bytes;
        public final String recoveryKey;
        public final Session session;
        private Created(byte[] bytes, String recoveryKey, Session session) {
            this.bytes = bytes; this.recoveryKey = recoveryKey; this.session = session;
        }
    }

    public static final class Session {
        private byte[] header;
        private byte[] payload;
        private byte[] dek;
        private Session(byte[] header, byte[] dek, byte[] payload) { this.header = header; this.dek = dek; this.payload = payload; }

        public synchronized byte[] decryptPayload() throws Exception {
            ensureOpen();
            long n = readLong(header, 103);
            if (n < TAG || n > MAX_FILE || HEADER + n > MAX_FILE) throw new Exception("Tamaño no válido");
            byte[] nonce = Arrays.copyOfRange(header, 91, 103);
            byte[] plain = crypt(Cipher.DECRYPT_MODE, dek, nonce, header, payload, 0, payload.length);
            return plain;
        }

        public synchronized byte[] replacePayload(byte[] plain) throws Exception {
            ensureOpen();
            byte[] previous = decryptPayload();
            Arrays.fill(previous, (byte) 0);
            byte[] nextHeader = header.clone();
            byte[] oldNonce = Arrays.copyOfRange(header, 91, 103);
            byte[] nonce = new byte[12];
            do { RNG.nextBytes(nonce); }
            while (Arrays.equals(nonce, oldNonce) || Arrays.equals(nonce, Arrays.copyOfRange(header, 51, 63)) || Arrays.equals(nonce, Arrays.copyOfRange(header, 79, 91)));
            System.arraycopy(nonce, 0, nextHeader, 91, 12);
            long cipherLength = (long) plain.length + TAG;
            ByteBuffer.wrap(nextHeader, 103, 8).order(ByteOrder.BIG_ENDIAN).putLong(cipherLength);
            byte[] sealed = crypt(Cipher.ENCRYPT_MODE, dek, nonce, nextHeader, plain, 0, plain.length);
            byte[] out = new byte[HEADER + sealed.length];
            System.arraycopy(nextHeader, 0, out, 0, HEADER);
            System.arraycopy(sealed, 0, out, HEADER, sealed.length);
            Arrays.fill(header, (byte) 0);
            Arrays.fill(payload, (byte) 0);
            header = nextHeader;
            payload = sealed.clone();
            Arrays.fill(sealed, (byte) 0);
            return out;
        }

        public synchronized byte[] openSnapshot(byte[] file) throws Exception {
            ensureOpen();
            if(file==null||file.length<HEADER+TAG||file.length>MAX_FILE)throw new Exception("Archivo incompleto");
            if(!Arrays.equals(Arrays.copyOfRange(file,0,91),Arrays.copyOfRange(header,0,91))||
               !Arrays.equals(Arrays.copyOfRange(file,CORE,HEADER),Arrays.copyOfRange(header,CORE,HEADER)))throw new Exception("La bóveda cambió desde que se abrió");
            long n=readLong(file,103);if(n<TAG||n!=file.length-HEADER)throw new Exception("Tamaño no válido");
            byte[] nonce=Arrays.copyOfRange(file,91,103);byte[] aad=Arrays.copyOfRange(file,0,HEADER);
            return crypt(Cipher.DECRYPT_MODE,dek,nonce,aad,file,HEADER,(int)n);
        }

        public synchronized void destroy() {
            if (header != null) Arrays.fill(header, (byte) 0);
            if (payload != null) Arrays.fill(payload, (byte) 0);
            if (dek != null) Arrays.fill(dek, (byte) 0);
            header = null; payload = null; dek = null;
        }
        private void ensureOpen() { if (header == null || dek == null) throw new IllegalStateException("Bóveda bloqueada"); }
    }

    public static Created create(byte[] plaintext, byte[] password) throws Exception {
        if (password == null || password.length == 0) throw new Exception("La contraseña maestra no puede estar vacía");
        byte[] core = new byte[CORE];
        System.arraycopy(MAGIC, 0, core, 0, MAGIC.length);
        ByteBuffer.wrap(core).order(ByteOrder.BIG_ENDIAN).putShort(8, (short)1).putInt(10, 65536).putInt(14, 3);
        core[18] = 1;
        randomInto(core,19,16); randomInto(core,35,16); randomInto(core,51,12);
        randomInto(core,63,16); randomInto(core,79,12); randomInto(core,91,12);
        ByteBuffer.wrap(core, 103, 8).order(ByteOrder.BIG_ENDIAN).putLong((long) plaintext.length + TAG);
        byte[] recovery = new byte[32], dek = new byte[DEK];
        RNG.nextBytes(recovery); RNG.nextBytes(dek);
        byte[] pwKey = derive(password, Arrays.copyOfRange(core,35,51), 65536, 3, 1);
        byte[] recoveryKey = derive(recovery, Arrays.copyOfRange(core,63,79), 65536, 3, 1);
        byte[] pwWrap = crypt(Cipher.ENCRYPT_MODE,pwKey,Arrays.copyOfRange(core,51,63),Arrays.copyOfRange(core,0,91),dek,0,dek.length);
        byte[] recoveryWrap = crypt(Cipher.ENCRYPT_MODE,recoveryKey,Arrays.copyOfRange(core,79,91),Arrays.copyOfRange(core,0,91),dek,0,dek.length);
        byte[] header = new byte[HEADER];
        System.arraycopy(core,0,header,0,CORE); System.arraycopy(pwWrap,0,header,CORE,48); System.arraycopy(recoveryWrap,0,header,CORE+48,48);
        byte[] encrypted = crypt(Cipher.ENCRYPT_MODE,dek,Arrays.copyOfRange(core,91,103),header,plaintext,0,plaintext.length);
        byte[] file = new byte[HEADER+encrypted.length]; System.arraycopy(header,0,file,0,HEADER); System.arraycopy(encrypted,0,file,HEADER,encrypted.length);
        String displayed = Base64.getUrlEncoder().withoutPadding().encodeToString(recovery);
        Session session=new Session(header.clone(),dek,Arrays.copyOfRange(file,HEADER,file.length));
        Arrays.fill(core,(byte)0); Arrays.fill(pwKey,(byte)0); Arrays.fill(recoveryKey,(byte)0); Arrays.fill(recovery,(byte)0); Arrays.fill(pwWrap,(byte)0); Arrays.fill(recoveryWrap,(byte)0); Arrays.fill(encrypted,(byte)0);
        return new Created(file, displayed, session);
    }

    public static Session unlock(byte[] file, byte[] secret, boolean recoveryKey) throws Exception {
        if (file == null || file.length < HEADER + TAG || file.length > MAX_FILE) throw new Exception("Archivo no válido");
        for (int i=0;i<MAGIC.length;i++) if(file[i]!=MAGIC[i]) throw new Exception("No es una bóveda CapyVault");
        if (((file[8]&255)<<8 | (file[9]&255)) != 1) throw new Exception("Versión de bóveda no compatible");
        long declared=readLong(file,103);
        if(declared<TAG || declared!=file.length-HEADER) throw new Exception("Archivo incompleto o dañado");
        int memory=readInt(file,10), iterations=readInt(file,14), lanes=file[18]&255;
        if(memory<8192 || memory>262144 || iterations<1 || iterations>10 || lanes<1 || lanes>16) throw new Exception("Parámetros Argon2id no válidos");
        int saltOffset=recoveryKey?63:35, nonceOffset=recoveryKey?79:51, wrapOffset=CORE+(recoveryKey?48:0);
        byte[] wrapping=derive(secret,Arrays.copyOfRange(file,saltOffset,saltOffset+16),memory,iterations,lanes);
        byte[] dek=crypt(Cipher.DECRYPT_MODE,wrapping,Arrays.copyOfRange(file,nonceOffset,nonceOffset+12),Arrays.copyOfRange(file,0,91),file,wrapOffset,48);
        Arrays.fill(wrapping,(byte)0);
        if(dek.length!=DEK){Arrays.fill(dek,(byte)0);throw new Exception("Clave no válida");}
        Session s=new Session(Arrays.copyOfRange(file,0,HEADER),dek,Arrays.copyOfRange(file,HEADER,file.length));
        byte[] payload=s.decryptPayload(); Arrays.fill(payload,(byte)0);
        return s;
    }

    public static byte[] recoveryBytes(String key) throws Exception {
        byte[] b=Base64.getUrlDecoder().decode(key.trim()); if(b.length!=32) throw new Exception("Clave de recuperación no válida"); return b;
    }

    private static byte[] derive(byte[] secret,byte[] salt,int memory,int iterations,int lanes) throws Exception {
        Argon2Parameters params=new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13).withMemoryAsKB(memory).withIterations(iterations).withParallelism(lanes).withSalt(salt).build();
        Argon2BytesGenerator gen=new Argon2BytesGenerator(); gen.init(params); byte[] out=new byte[32]; gen.generateBytes(secret,out); params.clear(); return out;
    }
    private static byte[] crypt(int mode,byte[] key,byte[] nonce,byte[] aad,byte[] input,int offset,int len) throws Exception {
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(mode,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce)); cipher.updateAAD(aad); return cipher.doFinal(input,offset,len);
    }
    private static long readLong(byte[] b,int off){return ByteBuffer.wrap(b,off,8).order(ByteOrder.BIG_ENDIAN).getLong();}
    private static int readInt(byte[] b,int off){return ByteBuffer.wrap(b,off,4).order(ByteOrder.BIG_ENDIAN).getInt();}
    private static void randomInto(byte[] dest,int offset,int length){byte[] r=new byte[length];RNG.nextBytes(r);System.arraycopy(r,0,dest,offset,length);Arrays.fill(r,(byte)0);}
}
