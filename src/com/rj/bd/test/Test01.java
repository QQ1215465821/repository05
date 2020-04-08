package com.rj.bd.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
/**
 * @description  java实现非对称加密
 * @author 刘鹏
 * @time  2020-4-8 22:29:23
 */
public class Test01 {
    public static void main(String[] args) throws Exception {
        //生成公钥和私钥
        Map<String, String> keyPair = getKeyPair();
        String publicKeyString = keyPair.get("publicKeyString");
        String privateKeyString = keyPair.get("privateKeyString");
        String content = "河北软件职业技术学院";
        //加密字符串
        String contentOfEncrypt = encrypt(content, publicKeyString);
        //解密字符串
        String contentOfDecrypt = decrypt(contentOfEncrypt, privateKeyString);

        System.out.println("公钥字符串---" + publicKeyString);
        System.out.println("私钥字符串---" + privateKeyString);
        System.out.println("原始字符串---" + content);
        System.out.println("字符串加密后---" + contentOfEncrypt);
        System.out.println("字符串解密后---" + contentOfDecrypt);
    }

    /**
     * 生成密钥对
     * @throws NoSuchAlgorithmException
     */
    public static Map<String, String> getKeyPair() throws NoSuchAlgorithmException {
        Map<String, String> keyMap = new HashMap<String , String>();
        // 通过RSA算法生成密钥对生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        // 初始化密钥对生成器
        keyPairGenerator.initialize(1024, new SecureRandom());
        // 生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥
        String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));
        // 得到私钥字符串
        String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));
        // 将公钥和私钥保存到Map
        keyMap.put("publicKeyString", publicKeyString);
        keyMap.put("privateKeyString", privateKeyString);
        return keyMap;
    }

    /**
     * 对字符串进行加密
     * @param str 加密字符串
     * @param publicKeyStr 公钥字符串
     * @return
     * @throws Exception
     */
    public static String encrypt(String str, String publicKeyStr) throws Exception {
        //根据公钥字符串获取公钥对象
        PublicKey publicKey = getPublicKey(publicKeyStr);
        //获取RSA算法的密码实例
        Cipher cipher = Cipher.getInstance("RSA");
        //初始密码实例并设置加密模式
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(str.getBytes("UTF-8"));
        String outStr = Base64.encodeBase64String(bytes);
        return outStr;
    }

    /**
     * 对字符串进行解密
     * @param str 要解密的字符串
     * @param privateKeyStr 私钥字符串
     * @return
     * @throws Exception
     */
    public static String decrypt(String str, String privateKeyStr) throws Exception {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
        //根据私钥字符串获取私钥对象
        PrivateKey privateKey = getPrivateKey(privateKeyStr);
        //获取RSA算法的密码实例
        Cipher cipher = Cipher.getInstance("RSA");
        //初始密码实例并设置解密模式
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        String outStr = new String(cipher.doFinal(inputByte));
        return outStr;
    }

    /**
     * 根据私钥字符串获取私钥对象
     * @param privateKeyStr 私钥字符串
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PrivateKey getPrivateKey(String privateKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decoded = Base64.decodeBase64(privateKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 根据公钥字符串获取公钥对象
     * @param publicKeyStr 公钥字符串
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PublicKey getPublicKey(String publicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decoded = Base64.decodeBase64(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new X509EncodedKeySpec(decoded);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }
}
