package com.juwu.myutil

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import android.view.View
import com.juwu.myutil.fileutils.utils.*
import kotlinx.android.synthetic.main.activity_main.*
import org.apache.commons.lang3.StringUtils

class MainActivity : AppCompatActivity(), View.OnClickListener {

    private val key = "123456789012345"
    private val aesHelper = AESHelper(key)
    private val rsaHelper = RSAHelper()
    private val desHelper = DESHelper(key)
    private val md5Helper = MD5Helper()
    private val shaHelper = SHAHelper()
    private val xorHelper = XORHelper()

    lateinit var privateKey: String
    lateinit var publicKey: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        tvAes.setOnClickListener(this)
        tvRsa.setOnClickListener(this)
        tvRsa1.setOnClickListener(this)
        tvDes.setOnClickListener(this)
        tvMd5.setOnClickListener(this)
        tvSHA.setOnClickListener(this)
        tvXor.setOnClickListener(this)
        val key = rsaHelper.generateRSAKeyPair()
        privateKey = Base64.encodeToString(key.private.encoded, Base64.DEFAULT)//key.private//c884c...ec
        publicKey = Base64.encodeToString(key.public.encoded, Base64.DEFAULT)//key.public//c884cf7...27
    }

    override fun onClick(v: View?) {
        if (v == null) return
        var tag = v.tag
        if (tag == null) tag = "false"
        when (v.id) {
            R.id.tvAes -> {
                if (StringUtils.equals(tag.toString(), "true")) {
                    //解密
                    val encrypt = tvAesResult.text.toString()
                    etAes.setText(aesHelper.decrypt(encrypt))
//                    etAes.setText(aes.decrypt(encrypt))
                    tvAesResult.text = ""
                    tvAes.tag = "false"
                    tvAes.text = "AES加密"
                } else {
                    //加密
                    val express = etAes.text.toString()
                    tvAesResult.text = aesHelper.encrypt(express)
//                    tvAesResult.text = aes.encrypt(express.toByteArray())
                    etAes.setText("")
                    tvAes.tag = "true"
                    tvAes.text = "AES解密"
                }
            }
            R.id.tvRsa -> {
                if (StringUtils.equals(tag.toString(), "true")) {
                    //解密
                    val encrypt = tvRsaResult.text.toString()
//                    etRsa.setText(rsaHelper.decryptedToStrByPrivate(encrypt, rsaHelper.keyStrToPrivate(RSAHelper.PRIVATE_KEY_STR)))
                    etRsa.setText(rsaHelper.decryptedToStrByPrivate(encrypt, rsaHelper.keyStrToPrivate(privateKey)))
                    tvRsaResult.text = ""
                    tvRsa.tag = "false"
                    tvRsa.text = "REA公钥加密私钥解密-公钥加密"
                } else {
                    //加密
                    val express = etRsa.text.toString()
//                    tvRsaResult.text = rsaHelper.encryptDataByPublicKey(express, rsaHelper.keyStrToPublicKey(RSAHelper.PUBLIC_KEY_STR))
                    tvRsaResult.text = rsaHelper.encryptDataByPublicKey(express, rsaHelper.keyStrToPublicKey(publicKey))
                    etRsa.setText("")
                    tvRsa.tag = "true"
                    tvRsa.text = "REA公钥加密私钥解密-私钥解密"
                }
            }
            R.id.tvRsa1 -> {
                if (StringUtils.equals(tag.toString(), "true")) {
                    //解密
                    val encrypt = tvRsaResult1.text.toString()
                    etRsa1.setText(rsaHelper.decryptDataByPublicKey(encrypt, rsaHelper.keyStrToPublicKey(RSAHelper.PUBLIC_KEY_STR)))
                    tvRsaResult1.text = ""
                    tvRsa1.tag = "false"
                    tvRsa1.text = "REA公钥解密私钥加密-私钥加密"
                } else {
                    //加密
                    val express = etRsa1.text.toString()
                    tvRsaResult1.text = rsaHelper.encryptDataByPrivateKey(express, rsaHelper.keyStrToPrivate(RSAHelper.PRIVATE_KEY_STR))
                    etRsa1.setText("")
                    tvRsa1.tag = "true"
                    tvRsa1.text = "REA公钥解密私钥加密-公钥解密"
                }
            }

            R.id.tvDes -> {
                if (StringUtils.equals(tag.toString(), "true")) {
                    //解密
                    val encrypt = tvDesResult.text.toString()
                    etDes.setText(desHelper.decrypt(encrypt))
                    tvDesResult.text = ""
                    tvDes.tag = "false"
                    tvDes.text = "DES加密"
                } else {
                    //加密
                    val express = etDes.text.toString()
                    tvDesResult.text = desHelper.encrypt(express)
                    etDes.setText("")
                    tvDes.tag = "true"
                    tvDes.text = "DES解密"
                }
            }

            R.id.tvMd5 -> {
                //加密
                val express = etMd5.text.toString()
                tvMd5Result.text = md5Helper.md5(express)
                tvMd5.tag = "true"
                tvMd5.text = "MD5加密"
            }

            R.id.tvSHA -> {
                //加密
                val express = etSHA.text.toString()
                tvSHAResult.text = "SHA:" + shaHelper.SHA(express) +
                        "\nSHA-256:" + shaHelper.SHA256(express) +
                        "\nSHA-384:" + shaHelper.SHA384(express) +
                        "\nSHA-512:" + shaHelper.SHA512(express)
                tvMd5.tag = "true"
            }

            R.id.tvXor -> {
                if (StringUtils.equals(tag.toString(), "true")) {
                    //解密
                    val encrypt = tvXorResult.text.toString()
//                    etXor.setText(xorHelper.encryptOrDecrypt(encrypt))
                    etXor.setText(xorHelper.decryptKey(encrypt))
                    tvXorResult.text = ""
                    tvXor.tag = "false"
                    tvXor.text = "XOR加密"
                } else {
                    //加密
                    val express = etXor.text.toString()
//                    tvXorResult.text = xorHelper.encryptOrDecrypt(express)
                    tvXorResult.text = xorHelper.encryptKey(express)
                    etXor.setText("")
                    tvXor.tag = "true"
                    tvXor.text = "XOR解密"
                }
            }

        }
    }


}
