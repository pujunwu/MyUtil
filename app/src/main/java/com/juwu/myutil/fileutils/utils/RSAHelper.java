package com.juwu.myutil.fileutils.utils;

import android.util.Base64;

import org.apache.commons.lang3.StringUtils;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * ===============================
 * 描    述：RSA加密解密帮助类
 * 作    者：pjw
 * 创建日期：2018/2/5 17:36
 * 获取Cipher实例时，传入的字符串并不是任意的，必须为"algorithm/mode/padding"，意为"算法/加密模式/填充方式"
 * 需要Android支持该组合模式，关于RSA的所有合法形式：http://blog.csdn.net/jungle_pig/article/details/72621237
 * 加密的结果byte[]要Base64.encode一下然后 new String(result)
 * 解密的结果byte[]直接 new String(result)
 *
 1.随机选择两个大质数p和q，p不等于q，计算N=pq；
 2.选择一个大于1小于N的自然数e，e必须与(p-1)(q-1)互素。
 3.用公式计算出d：d×e = 1 (mod (p-1)(q-1)) 。
 4.销毁p和q。
 最终得到的N和e就是“公钥”，d就是“私钥”，发送方使用N去加密数据，接收方只有使用d才能解开数据内容。
 * ===============================
 */
public class RSAHelper {

    //字符串公钥，可以直接保存在客户端
    public static final String PUBLIC_KEY_STR = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDq+LD0E5aRw9O6oElL2jvb7OGxOACxdcZZnvwN4L+Pv3aM4KSGl4Q7zDSAj/ViaQDC6Y0f3GXiAPIoGPcUnIcm/mpiNZ85NHgoYtgwpP4o0nAEarEUu/YPfdzYAVF7ku+azVJPxelbgxQV0tlamKk0H1COHi3nIdgbusaAvEarMZfFMk25MKB03LrWBjJ9ydDFOjvfokigdxvBDmFhyTsgU1QlEsDPKNFqRS+nrDx6z6j5Xpfeq3P59sQJLE3Hd6YGbUxJB4eVDua5KWS6Fw/5mFWfGBQmdMqm4dUEXlCAYr1U6GVtJJ+amSfzwP1U2D5KD7xCy8N3MJRlgsN2iFwIDAQAB";
    //字符串密钥，通常保存在服务器，这里为了方便演示，直接保存在客户端
    public static final String PRIVATE_KEY_STR = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCsOr4sPQTlpHD07qgSUvaO9vs4bE4ALF1xlme/A3gv4+/dozgpIaXhDvMNICP9WJpAMLpjR/cZeIA8igY9xSchyb+amI1nzk0eChi2DCk/ijScARqsRS79g993NgBUXuS75rNUk/F6VuDFBXS2VqYqTQfUI4eLech2Bu6xoC8Rqsxl8UyTbkwoHTcutYGMn3J0MU6O9+iSKB3G8EOYWHJOyBTVCUSwM8o0WpFL6esPHrPqPlel96rc/n2xAksTcd3pgZtTEkHh5UO5rkpZLoXD/mYVZ8YFCZ0yqbh1QReUIBivVToZW0kn5qZJ/PA/VTYPkoPvELLw3cwlGWCw3aIXAgMBAAECggEABrWPHPgPjcaXI+N8JqKWukECzlLhwv33cepTBkzjTLJLcM3f7TJDXP4RF8zNuhvOfnundyChjpt0G2ehEJzyhk1uql4Q/B88P9RS3ByjKrd+jyk32cgkKXoOpX00DBVaQbud9siAmqxxuxsYTdYYSQORL4Fm0VcgKQDiIYdE7iIx0G+CTO8ClWKNwQsY82GdEd1DizGVz7p747k5doSiSi6Bu7YHXk9d5kiFeGhBRXO2KQt2ZfyVsRbDuKdyWvpMeRKFE8dsSvgEC1Cli8ThGjPM1PLJYmkWRGwFu+Rorua04u6ss6zqEam08pOm0qzfoKJ7ZvaiIhbecjadRC9qeQKBgQDYBeDxPQu1IwA92KtcazSCGXCk4cf3IqlDnlT/kVTdy5RsVa93mq2KAYSlTOq+6b58qPP5RlNx0kbWZUo4eyqy3s7GHcDI9kkSgljUKUboFNvtD4ROMgJ8f8xauEsKb1MOkS940JTJ4OfdzHfzOLj/DTfyxFl58AJGfUyi7hfJQwKBgQDMGiPvzJPFzvOL+jQPbF3B+ttlJLOAmHpgzlkqlWTD3EQC7EW9AZiuIlk0mgxXMWkULvpn2sem3/RwTbUp6omaz2/vWZE9UXUvLXAMWy44zNNaXUP/rROxvpFXuvD63N2BevHzL4t2GDCO54yrXq5vNkjqRBTee8sfqxpOLP68nQKBgQCqIh8h/6Eb3OAQ1XdIh0pIeH7F7OhPVGYY0jdBPJWpRO+1TtquCQ1KFp4Ajg6Ho5IZnfrgRSntB94wdn+48hAT5fTWBZLS811jjXMmTQgCOoNnNgROjYZ1xTUN8f1vz3OLkn7f2O6F/HLAtYt27CKPBTseINQTfBpep8pWu8vR/wKBgBWB46uPSTsc9bkYYogFiVO5lYjw9yFj7/FnjSnZmEazXU9ZinfCRU6EPBY47Xf6svH3iVeMTGGfU+jJp3+FQX7YwRjdvVpSzSBtj1MeAJ7nppXtIg89M8gVJsex4VbuE0FjrT9NEUsefW9xovckAQmjFMfq6LARJ3Rs2VbHkwhZAoGBANOj4V5tJzcZmoav14WfNTs5EPq+W8ZR73NDaffTq5oWytqYaQoG/haISANySHL5mF+PIZ5lKBRHnzO6u2tk+ir/LjmMqJT5WzhtQqAv8jkogkxzD8nyXtiIyRyf8s/oI2UQwdNWIxqQKLIrqGQ2HCuSC1QquZD1EmuIYjE6/w5j";
    //进行Base64转码时的flag设置，默认为Base64.DEFAULT
    private static int sBase64Mode = Base64.DEFAULT;

    /**
     * 将字符串形式的公钥转换为公钥对象
     *
     * @param publicKeyStr 加密公钥key
     * @return 公钥对象
     */
    public PublicKey keyStrToPublicKey(String publicKeyStr) {
        PublicKey publicKey = null;
        byte[] keyBytes = Base64.decode(publicKeyStr, sBase64Mode);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * 将字符串形式的私钥，转换为私钥对象
     *
     * @param privateKeyStr 加密私钥key
     * @return 私钥对象
     */
    public PrivateKey keyStrToPrivate(String privateKeyStr) {
        PrivateKey privateKey = null;
        byte[] keyBytes = Base64.decode(privateKeyStr, sBase64Mode);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * 产生密钥对
     * 密钥长度，小于1024长度的密钥已经被证实是不安全的，通常设置为1024或者2048，建议2048
     */
    public KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            //设置密钥长度
            keyPairGenerator.initialize(2048);
            //产生密钥对
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 加密或解密数据的通用方法
     *
     * @param srcData 待处理的数据
     * @param key     公钥或者私钥
     * @param mode    指定是加密还是解密，值为Cipher.ENCRYPT_MODE或者Cipher.DECRYPT_MODE
     * @return 处理后的字符串
     */
    private byte[] processData(byte[] srcData, Key key, int mode) {
        //构建Cipher对象，需要传入一个字符串，格式必须为"algorithm/mode/padding"或者"algorithm/",意为"算法/加密模式/填充方式"
        try {
            Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            //初始化Cipher，mode指定是加密还是解密，key为公钥或私钥
            cipher.init(mode, key);
            //处理数据
            return cipher.doFinal(srcData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /********************************公钥*******************************/

    /**
     * 使用公钥加密数据，结果用Base64转码
     */
    public String encryptDataByPublicKey(String srcData, PublicKey publicKey) {
        byte[] resultBytes = processData(srcData.getBytes(), publicKey, Cipher.ENCRYPT_MODE);
        return Base64.encodeToString(resultBytes, sBase64Mode);
    }

    /**
     * 使用公钥解密，返回解密数据
     */
    public String decryptDataByPublicKey(String encryptedData, PublicKey publicKey) {
        byte[] bytes = Base64.decode(encryptedData, sBase64Mode);
        byte[] result = processData(bytes, publicKey, Cipher.DECRYPT_MODE);
        return new String(result);
    }

    /********************************私钥*******************************/

    /**
     * 使用私钥进行解密，解密数据转换为字符串，使用utf-8编码格式
     */
    public String decryptedToStrByPrivate(String encryptedData, PrivateKey privateKey) {
        if (StringUtils.isEmpty(encryptedData)) return "";
        byte[] bytes = Base64.decode(encryptedData, sBase64Mode);
        bytes = processData(bytes, privateKey, Cipher.DECRYPT_MODE);
        if (bytes == null) return encryptedData;
        return new String(bytes);
    }

    /**
     * 使用私钥加密，结果用Base64转码
     */
    public String encryptDataByPrivateKey(String srcData, PrivateKey privateKey) {
        byte[] resultBytes = processData(srcData.getBytes(), privateKey, Cipher.ENCRYPT_MODE);
        return Base64.encodeToString(resultBytes, sBase64Mode);
    }

}
