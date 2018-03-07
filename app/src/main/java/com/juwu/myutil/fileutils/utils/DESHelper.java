package com.juwu.myutil.fileutils.utils;

import android.util.Base64;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ===============================
 * 描    述：DES加密解密
 * 作    者：pjw
 * 创建日期：2018/2/6 17:33
 * 要保证在不同的平台上加密和解密的一致性需要做到以下三点
 * 1.加密和解密的密钥一致
 * 2.採用CBC模式的时候，要保证初始向量一致
 * 3.採用同样的填充模式
 * ===============================
 */
public class DESHelper {

    //秘钥
    private SecretKeySpec secretKey;
    //key
    private String key;

    public DESHelper(String key) {
        this.key = key;
        secretKey = keygenerate(key);
    }

    /**
     * 使用一个安全的随机数来产生一个密匙,密匙加密使用的
     */
    private byte[] getRawKey(byte[] seed) throws NoSuchAlgorithmException {
        // 获得一个随机数，传入的参数为默认方式。
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        // 设置一个种子,一般是用户设定的密码
        sr.setSeed(seed);
        // 获得一个key生成器（AES加密模式）
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        //DES固定格式为64bits，即8bytes。
        keyGen.init(64, sr);
        // 获得密匙
        SecretKey key = keyGen.generateKey();
        // 返回密匙的byte数组供加解密使用
        return key.getEncoded();
    }

    /**
     * 获取key
     *
     * @param passphrase 秘钥
     * @return key
     */
    private SecretKeySpec keygenerate(String passphrase) {
        SecretKeySpec sks = null;
        try {
            sks = new SecretKeySpec(getRawKey(passphrase.getBytes()), "DES");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sks;
    }

    /**
     * 加密
     *
     * @param data 需要加密字符串
     * @return 加密后的字符串
     */
    public String encrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
            byte[] bytes = cipher.doFinal(data.getBytes());
            return Base64.encodeToString(bytes, Base64.DEFAULT);
        } catch (Exception e) {
            return data;
        }
    }

    /**
     * DES算法，解密
     *
     * @param data 待解密字符串
     * @return 解密后的字节数组
     */
    public String decrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
            byte[] original = cipher.doFinal(Base64.decode(data.getBytes(), Base64.DEFAULT));
            return new String(original);
        } catch (Exception e) {
            return data;
        }
    }

}
