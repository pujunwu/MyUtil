package com.juwu.myutil.fileutils.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * ===============================
 * 描    述：SHA算法
 * 作    者：pjw
 * 创建日期：2018/2/8 11:51
 * <p>
 * SHA算法各个实现厂家:
 * 算法       摘要长度        实现方
 * SHA-1      160             JDK
 * SHA-224    224             Bouncy Castle
 * SHA-256    256             JDK
 * SHA-384    384             JDK
 * SHA-512    512             JDK
 * ===============================
 */
public class SHAHelper {

    /**
     * 字符串 SHA 加密
     */
    private String SHA(final String strText, String strType) {
        // 返回值
        String strResult = null;
        // 是否是有效字符串
        if (strText != null && strText.length() > 0) {
            try {
                // SHA 加密开始
                // 创建加密对象 并傳入加密類型
                MessageDigest messageDigest = MessageDigest.getInstance(strType);
                // 传入要加密的字符串
                messageDigest.update(strText.getBytes());
                // 得到 byte 類型结果
                byte byteBuffer[] = messageDigest.digest();
                // 將 byte 轉換爲 string
                StringBuilder strHexString = new StringBuilder();
                // 遍歷 byte buffer
                //对于数组，foreach按顺序从数组的第一个元素遍历到最后一个元素
                //对于Iterable容器，则依照迭代器的遍历顺序
                for (byte b : byteBuffer) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) {
                        strHexString.append('0');
                    }
                    strHexString.append(hex);
                }
                // 得到返回結果
                strResult = strHexString.toString();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return strResult;
    }

    /**
     * 传入文本内容，返回 SHA-256 串
     */
    public String SHA(final String strText) {
        return SHA(strText, "SHA");
    }

    /**
     * 传入文本内容，返回 SHA-256 串
     */
    public String SHA256(final String strText) {
        return SHA(strText, "SHA-256");
    }

    /**
     * 传入文本内容，返回 SHA-384 串
     */
    public String SHA384(final String strText) {
        return SHA(strText, "SHA-384");
    }

    /**
     * 传入文本内容，返回 SHA-512 串
     */
    public String SHA512(final String strText) {
        return SHA(strText, "SHA-512");
    }


}
