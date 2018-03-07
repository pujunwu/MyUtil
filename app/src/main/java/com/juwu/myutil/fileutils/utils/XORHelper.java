package com.juwu.myutil.fileutils.utils;

/**
 * ===============================
 * 描    述：异或加密
 * 作    者：pjw
 * 创建日期：2018/3/7 16:30
 * 异或运算中，如果某个字符（或数值）x 与 一个数值m 进行异或运算得到y，
 * 则再用y 与 m 进行异或运算就可以还原为 x ，因此应用这个原理可以实现数据的加密解密功能。
 * 场景：
 * 两个变量的互换（不借助第三个变量）
 * 数据的简单加密解密
 * ===============================
 */
public class XORHelper {

    /**
     * 固定key加密
     *
     * @param bytes
     * @return
     */
    public byte[] encrypt(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        int len = bytes.length;
        int key = 0x15;
        for (int i = 0; i < len; i++) {
            bytes[i] ^= key;
        }
        return bytes;
    }

    /**
     * 固定key：加密/解密
     *
     * @param string 需要加密串/加密后的串
     */
    public String encryptOrDecrypt(String string) {
        return new String(encrypt(string.getBytes()));
    }


    /**
     * 不固定key加密
     *
     * @param bytes 需要加密
     * @return 加密后
     */
    public byte[] encryptKey(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        int len = bytes.length;
        int key = 0x15;
        for (int i = 0; i < len; i++) {
            bytes[i] = (byte) (bytes[i] ^ key);
            key = bytes[i];
        }
        return bytes;
    }

    /**
     * 不固定key加密:字符串加密
     *
     * @param string 需要加密的字符串
     * @return 加密后的字符串
     */
    public String encryptKey(String string) {
        return new String(encryptKey(string.getBytes()));
    }


    /**
     * 不固定key解密
     *
     * @param bytes 需要解密
     * @return 解密后
     */
    public byte[] decryptKey(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        int len = bytes.length;
        int key = 0x15;
        for (int i = len - 1; i > 0; i--) {
            bytes[i] = (byte) (bytes[i] ^ bytes[i - 1]);
        }
        bytes[0] = (byte) (bytes[0] ^ key);
        return bytes;
    }

    /**
     * 不固定key解密:字符串
     *
     * @param string 需要解密的字符串
     * @return 解密后的字符串
     */
    public String decryptKey(String string) {
        return new String(decryptKey(string.getBytes()));
    }


}
