//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package cryptolib;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public final class Dukpt {
    public static final int NUM_OVERWRITES = 3;

    public Dukpt() {
    }

    public static byte[] computeKey(BitSet IK, BitSet ksn, BitSet keyRegisterBitmask, BitSet dataVariantBitmask) throws Exception {
        BitSet key = _getCurrentKey(IK, ksn, keyRegisterBitmask, dataVariantBitmask);
        byte[] rkey = toByteArray(key);
        obliviate(ksn);
        obliviate(IK);
        obliviate(key);
        return rkey;
    }

    public static BitSet _getCurrentKey(BitSet initialKey, BitSet ksn, BitSet keyRegisterBitmask, BitSet dataVariantBitmask) throws Exception {
        BitSet key = initialKey.get(0, initialKey.bitSize());
        BitSet counter = ksn.get(0, ksn.bitSize());
        counter.clear(59, ksn.bitSize());

        for(int i = 59; i < ksn.bitSize(); ++i) {
            if (ksn.get(i)) {
                counter.set(i);
                BitSet tmp = _nonReversibleKeyGenerationProcess(key, counter.get(16, 80), keyRegisterBitmask);
                obliviate(key);
                key = tmp;
            }
        }

        key.xor(dataVariantBitmask);
        obliviate(counter);
        return key;
    }

    private static BitSet _nonReversibleKeyGenerationProcess(BitSet p_key, BitSet data, BitSet keyRegisterBitmask) throws Exception {
        BitSet keyreg = p_key.get(0, p_key.bitSize());
        BitSet reg1 = data.get(0, data.bitSize());
        BitSet reg2 = reg1.get(0, 64);
        reg2.xor(keyreg.get(64, 128));
        reg2 = toBitSet(encryptDes(toByteArray(keyreg.get(0, 64)), toByteArray(reg2)));
        reg2.xor(keyreg.get(64, 128));
        keyreg.xor(keyRegisterBitmask);
        reg1.xor(keyreg.get(64, 128));
        reg1 = toBitSet(encryptDes(toByteArray(keyreg.get(0, 64)), toByteArray(reg1)));
        reg1.xor(keyreg.get(64, 128));
        byte[] reg1b = toByteArray(reg1);
        byte[] reg2b = toByteArray(reg2);
        byte[] key = concat(reg1b, reg2b);
        BitSet rkey = toBitSet(key);
        obliviate(reg1);
        obliviate(reg2);
        obliviate(reg1b);
        obliviate(reg2b);
        obliviate(key);
        obliviate(keyreg);
        return rkey;
    }

    public static byte[] encryptDes(byte[] key, byte[] data, boolean padding) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        SecretKey encryptKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(key));
        Cipher encryptor;
        if (padding) {
            encryptor = Cipher.getInstance("DES/CBC/PKCS5Padding");
        } else {
            encryptor = Cipher.getInstance("DES/CBC/NoPadding");
        }

        encryptor.init(1, encryptKey, iv);
        return encryptor.doFinal(data);
    }

    public static byte[] decryptDes(byte[] key, byte[] data, boolean padding) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        SecretKey decryptKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(key));
        Cipher decryptor;
        if (padding) {
            decryptor = Cipher.getInstance("DES/CBC/PKCS5Padding");
        } else {
            decryptor = Cipher.getInstance("DES/CBC/NoPadding");
        }

        decryptor.init(2, decryptKey, iv);
        return decryptor.doFinal(data);
    }

    public static byte[] encryptDes(byte[] key, byte[] data) throws Exception {
        return encryptDes(key, data, false);
    }

    public static byte[] decryptDes(byte[] key, byte[] data) throws Exception {
        return decryptDes(key, data, false);
    }

    public static byte[] encryptTripleDes(byte[] key, byte[] data, boolean padding) throws Exception {
        BitSet bskey = toBitSet(key);
        BitSet k1;
        BitSet k2;
        BitSet k3;
        if (bskey.bitSize() == 64) {
            k1 = bskey.get(0, 64);
            k2 = k1;
            k3 = k1;
        } else if (bskey.bitSize() == 128) {
            k1 = bskey.get(0, 64);
            k2 = bskey.get(64, 128);
            k3 = k1;
        } else {
            if (bskey.bitSize() != 192) {
                throw new InvalidParameterException("Key is not 8/16/24 bytes long.");
            }

            k1 = bskey.get(0, 64);
            k2 = bskey.get(64, 128);
            k3 = bskey.get(128, 192);
        }

        byte[] kb1 = toByteArray(k1);
        byte[] kb2 = toByteArray(k2);
        byte[] kb3 = toByteArray(k3);
        byte[] key16 = concat(kb1, kb2);
        byte[] key24 = concat(key16, kb3);
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        SecretKey encryptKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(key24));
        Cipher encryptor;
        if (padding) {
            encryptor = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        } else {
            encryptor = Cipher.getInstance("DESede/CBC/NoPadding");
        }

        encryptor.init(1, encryptKey, iv);
        byte[] bytes = encryptor.doFinal(data);
        obliviate(k1);
        obliviate(k2);
        obliviate(k3);
        obliviate(kb1);
        obliviate(kb2);
        obliviate(kb3);
        obliviate(key16);
        obliviate(key24);
        obliviate(bskey);
        return bytes;
    }

    public static byte[] decryptTripleDes(byte[] key, byte[] data, boolean padding) throws Exception {
        BitSet bskey = toBitSet(key);
        BitSet k1;
        BitSet k2;
        BitSet k3;
        if (bskey.bitSize() == 64) {
            k1 = bskey.get(0, 64);
            k2 = k1;
            k3 = k1;
        } else if (bskey.bitSize() == 128) {
            k1 = bskey.get(0, 64);
            k2 = bskey.get(64, 128);
            k3 = k1;
        } else {
            if (bskey.bitSize() != 192) {
                throw new InvalidParameterException("Key is not 8/16/24 bytes long.");
            }

            k1 = bskey.get(0, 64);
            k2 = bskey.get(64, 128);
            k3 = bskey.get(128, 192);
        }

        byte[] kb1 = toByteArray(k1);
        byte[] kb2 = toByteArray(k2);
        byte[] kb3 = toByteArray(k3);
        byte[] key16 = concat(kb1, kb2);
        byte[] key24 = concat(key16, kb3);
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        SecretKey encryptKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(key24));
        Cipher decryptor;
        if (padding) {
            decryptor = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        } else {
            decryptor = Cipher.getInstance("DESede/CBC/NoPadding");
        }

        decryptor.init(2, encryptKey, iv);
        byte[] bytes = decryptor.doFinal(data);
        obliviate(k1);
        obliviate(k2);
        obliviate(k3);
        obliviate(kb1);
        obliviate(kb2);
        obliviate(kb3);
        obliviate(key16);
        obliviate(key24);
        obliviate(bskey);
        return bytes;
    }

    public static byte[] encryptTripleDes(byte[] key, byte[] data) throws Exception {
        return encryptTripleDes(key, data, false);
    }

    public static byte[] decryptTripleDes(byte[] key, byte[] data) throws Exception {
        return decryptTripleDes(key, data, false);
    }

    public static byte[] encryptAes(byte[] key, byte[] data, boolean padding) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        SecretKeySpec encryptKey = new SecretKeySpec(key, "AES");
        Cipher encryptor;
        if (padding) {
            encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } else {
            encryptor = Cipher.getInstance("AES/CBC/NoPadding");
        }

        encryptor.init(1, encryptKey, iv);
        return encryptor.doFinal(data);
    }

    public static byte[] decryptAes(byte[] key, byte[] data, boolean padding) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        SecretKeySpec decryptKey = new SecretKeySpec(key, "AES");
        Cipher decryptor;
        if (padding) {
            decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } else {
            decryptor = Cipher.getInstance("AES/CBC/NoPadding");
        }

        decryptor.init(2, decryptKey, iv);
        return decryptor.doFinal(data);
    }

    public static byte[] encryptAes(byte[] key, byte[] data) throws Exception {
        return encryptAes(key, data, false);
    }

    public static byte[] decryptAes(byte[] key, byte[] data) throws Exception {
        return decryptAes(key, data, false);
    }

    public static BitSet toBitSet(byte b) {
        BitSet bs = new BitSet(8);

        for(int i = 0; i < 8; ++i) {
            if (((long)b & 1L << i) > 0L) {
                bs.set(7 - i);
            }
        }

        return bs;
    }

    public static BitSet toBitSet(byte[] b) {
        BitSet bs = new BitSet(8 * b.length);

        for(int i = 0; i < b.length; ++i) {
            for(int j = 0; j < 8; ++j) {
                if (((long)b[i] & 1L << j) > 0L) {
                    bs.set(8 * i + (7 - j));
                }
            }
        }

        return bs;
    }

    public static byte toByte(BitSet b) {
        byte value = 0;

        for(int i = 0; i < b.bitSize(); ++i) {
            if (b.get(i)) {
                value = (byte)((int)((long)value | 1L << 7 - i));
            }
        }

        return value;
    }

    public static byte[] toByteArray(BitSet b) {
        int size = (int)Math.ceil((double)b.bitSize() / 8.0D);
        byte[] value = new byte[size];

        for(int i = 0; i < size; ++i) {
            value[i] = toByte(b.get(i * 8, Math.min(b.bitSize(), (i + 1) * 8)));
        }

        return value;
    }

    public static byte[] toByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];

        for(int i = 0; i < len; i += 2) {
            data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }

        return data;
    }

    public static String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "X", bi);
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];

        int i;
        for(i = 0; i < a.length; ++i) {
            c[i] = a[i];
        }

        for(i = 0; i < b.length; ++i) {
            c[a.length + i] = b[i];
        }

        return c;
    }

    public static void obliviate(BitSet b) {
        obliviate((BitSet)b, 3);
    }

    public static void obliviate(byte[] b) {
        obliviate((byte[])b, 3);
    }

    public static void obliviate(BitSet b, int n) {
        SecureRandom r = new SecureRandom();

        for(int i = 0; i < 3; ++i) {
            for(int j = 0; j < b.bitSize(); ++j) {
                b.set(j, r.nextBoolean());
            }
        }

    }

    public static void obliviate(byte[] b, int n) {
        for(int i = 0; i < n; ++i) {
            b[i] = 0;
            b[i] = 1;
        }

        SecureRandom r = new SecureRandom();

        for(int i = 0; i < n; ++i) {
            r.nextBytes(b);
        }

    }

    public static void main(String[] args) throws Exception {
    }

}
