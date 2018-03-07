package com.juwu.myutil.fileutils.utils;

import android.util.Base64;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ===============================
 * 描    述：AES加密解密帮助类
 * 作    者：pjw
 * 创建日期：2018/2/5 15:01
 * 设置密匙长度128位
 * 必须为128或192或256bits.也就是16或24或32byte
 * seed的原始字符串长度为：16或24或32
 * ===============================
 */
public class AESHelper {

    //加密还是解密 Cipher.ENCRYPT_MODE 、Cipher.DECRYPT_MODE
    private int cipherMode;
    //秘钥
    private SecretKeySpec secretKey;
    //进行Base64转码时的flag设置，默认为Base64.DEFAULT
    private static int sBase64Mode = Base64.DEFAULT;
    //key
    private String key;

    /**
     * AES加密解密帮助类
     *
     * @param key 秘钥
     */
    public AESHelper(String key) {
        secretKey = keygenerate(key);
        this.key = key;
    }

    /**
     * 设置模式
     *
     * @param cipherMode 加密：Cipher.ENCRYPT_MODE 解密：Cipher.DECRYPT_MODE
     */
    private void setCipherMode(int cipherMode) {
        this.cipherMode = cipherMode;
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
        // 设置密匙长度128位
        //必须为128或192或256bits.也就是16或24或32byte
        //seed的原始字符串长度为：16或24或32
        keyGen.init(128, sr);
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
            sks = new SecretKeySpec(getRawKey(passphrase.getBytes()), "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sks;
    }

    /**
     * 参数判断
     *
     * @throws IllegalArgumentException 抛出异常
     */
    private void param() throws IllegalArgumentException {
        if (cipherMode != Cipher.ENCRYPT_MODE && cipherMode != Cipher.DECRYPT_MODE) {
            throw new IllegalArgumentException("cipherMode 参数错误");
        }
    }

    private byte[] doFinal(byte[] source) {
        param();
        try {
            // 加密算法，加密模式和填充方式三部分或指定加密算
            //AES是加密方式 CBC是工作模式 PKCS5Padding是填充模式
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // 初始化模式为加密模式，并指定密匙
            cipher.init(cipherMode, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
            return cipher.doFinal(source);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /***************************字符串加密解密*************************/

    /**
     * 字符串加密
     *
     * @param source 需要加密的字符串
     * @return 加密后的字符串
     */
    public String encrypt(String source) throws Exception {
        byte[] result = encrypt(source.getBytes("UTF-8"));
        return Base64.encodeToString(result, sBase64Mode);
    }

    /**
     * byte数组加密
     *
     * @param source 需要加密的byte
     * @return 加密后的byte数组
     */
    private byte[] encrypt(byte[] source) {
        setCipherMode(Cipher.ENCRYPT_MODE);
        return doFinal(source);
    }

    /**
     * 字符串解密
     *
     * @param encrypted 需要解密的字符串
     * @return 解密后的字符串
     */
    public String decrypt(String encrypted) {
        byte[] result = decrypt(Base64.decode(encrypted.getBytes(), sBase64Mode));
        return new String(result);
    }

    /**
     * byte数组解密
     *
     * @param encrypted 需要解密的byte数组
     * @return 解密后的byte数组
     */
    private byte[] decrypt(byte[] encrypted) {
        setCipherMode(Cipher.DECRYPT_MODE);
        return doFinal(encrypted);
    }

    /***************************文件加密解密*************************/

    private SecretKeySpec keygenerateFile(String passphrase) {
        SecretKeySpec sks = null;
        try {
            byte[] key = passphrase.getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            sks = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return sks;
    }

    /**
     * 文件加密或者解密
     *
     * @param sourceFilePath 需要处理的源文件
     * @param targetFilePath 保存的文件路径
     * @return 成功返回true，反之返回false
     */
    private boolean aesCipherFile(String sourceFilePath, String targetFilePath) {
        if (FileUtils.getFileType(sourceFilePath) != FileUtils.TYPE_FILE) {
            throw new IllegalArgumentException("无效源文件");
        }
        FileChannel sourceFC = null;
        FileChannel targetFC = null;
        SecretKeySpec keySpec = keygenerateFile(key);
        try {
            sourceFC = new RandomAccessFile(new File(sourceFilePath), "r").getChannel();
            targetFC = new RandomAccessFile(new File(targetFilePath), "rw").getChannel();

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // 初始化模式为加密模式，并指定密匙
            cipher.init(cipherMode, keySpec, new IvParameterSpec(new byte[cipher.getBlockSize()]));

            ByteBuffer byteData = ByteBuffer.allocate(1024 * 20);
            //循环读取文件进行加密或者解密操作
            while (sourceFC.read(byteData) != -1) {
                // 通过通道读写交叉进行。
                // 将缓冲区准备为数据传出状态
                byteData.flip();
                byte[] byteList = new byte[byteData.remaining()];
                byteData.get(byteList, 0, byteList.length);
                //此处，若不使用数组加密解密会失败，因为当byteData达不到1024个时，加密方式不同对空白字节的处理也不相同，从而导致成功与失败。
                byte[] bytes = cipher.doFinal(byteList);
                targetFC.write(ByteBuffer.wrap(bytes));
                byteData.clear();
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (sourceFC != null) {
                try {
                    sourceFC.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (targetFC != null) {
                try {
                    targetFC.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return false;
    }

    /**
     * 文件加密
     *
     * @param sourceFilePath 需要加密的文件
     * @param targetFilePath 保存的文件路径
     * @return 成功返回true，反之返回false
     */
    public boolean encryptFile(String sourceFilePath, String targetFilePath) {
        setCipherMode(Cipher.ENCRYPT_MODE);
        return aesCipherFile(sourceFilePath, targetFilePath);
    }

    /**
     * 文件解密
     *
     * @param sourceFilePath 需要解密的文件
     * @param targetFilePath 保存的文件路径
     * @return 成功返回true，反之返回false
     */
    public boolean decryptFile(String sourceFilePath, String targetFilePath) {
        setCipherMode(Cipher.DECRYPT_MODE);
        return aesCipherFile(sourceFilePath, targetFilePath);
    }

}
