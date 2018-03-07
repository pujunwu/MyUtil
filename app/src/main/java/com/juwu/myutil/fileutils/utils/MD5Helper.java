package com.juwu.myutil.fileutils.utils;

import android.text.TextUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * ===============================
 * 描    述：MD5加密处理
 * 作    者：pjw
 * 创建日期：2018/2/8 10:16
 * <p>
 * MD5加密特点：
 * 压缩性：任意长度的数据，算出的MD5值长度都是固定的。
 * 容易计算：从原数据计算出MD5值很容易。
 * 抗修改性：对原数据进行任何改动，哪怕只修改1个字节，所得到的MD5值都有很大区别。
 * 强抗碰撞：已知原数据和其MD5值，想找到一个具有相同MD5值的数据（即伪造数据）是非常困难的
 * <p>
 * MD5应用场景：
 * 一致性验证
 * 数字签名
 * 安全访问认证
 * <p>
 * MD5的安全性：
 * 多次md5
 * 加盐
 * <p>
 * ===============================
 */
public class MD5Helper {

    /**
     * 字符串加密
     */
    public String md5(String string) {
        if (TextUtils.isEmpty(string)) {
            return "";
        }
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] bytes = md5.digest(string.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                String temp = Integer.toHexString(b & 0xff);
                if (temp.length() == 1) {
                    temp = "0" + temp;
                }
                sb.append(temp);
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * 多次MD5加密
     *
     * @param string 需要加密的原始字符串
     * @param times  需要加密的次数
     */
    public String md5(String string, int times) {
        if (TextUtils.isEmpty(string)) {
            return "";
        }
        String md5 = md5(string);
        for (int i = 0; i < times - 1; i++) {
            md5 = md5(md5);
        }
        return md5;
    }

    /**
     * MD5加盐
     * 加盐的方式也是多种多样
     * string+key（盐值key）然后进行MD5加密
     * 用string明文的hashcode作为盐，然后进行MD5加密
     * 随机生成一串字符串作为盐，然后进行MD5加密
     */
    public String md5(String string, String slat) {
        return md5(string + slat);
    }

    /**
     * 计算文件的md5值
     *
     * @param file 文件
     */
    public String md5(File file) {
        if (file == null || !file.isFile() || !file.exists()) {
            return "";
        }
        FileInputStream in = null;
        StringBuilder result = new StringBuilder();
        byte buffer[] = new byte[8192];
        int len;
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            in = new FileInputStream(file);
            while ((len = in.read(buffer)) != -1) {
                md5.update(buffer, 0, len);
            }
            byte[] bytes = md5.digest();
            for (byte b : bytes) {
                String temp = Integer.toHexString(b & 0xff);
                if (temp.length() == 1) {
                    temp = "0" + temp;
                }
                result.append(temp);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (null != in) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return result.toString();
    }

    /**
     * 采用nio的方式计算文件MD5值
     */
    public String md5Nio(File file) {
        if (file == null || !file.isFile() || !file.exists()) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        FileInputStream in = null;
        try {
            in = new FileInputStream(file);
            MappedByteBuffer byteBuffer = in.getChannel().map(FileChannel.MapMode.READ_ONLY, 0, file.length());
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(byteBuffer);
            byte[] bytes = md5.digest();
            for (byte b : bytes) {
                String temp = Integer.toHexString(b & 0xff);
                if (temp.length() == 1) {
                    temp = "0" + temp;
                }
                result.append(temp);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (null != in) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return result.toString();
    }

}
