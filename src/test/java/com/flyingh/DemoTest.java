package com.flyingh;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

public class DemoTest {

    @Test
    public void test29() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("DES");
        SecretKey secretKey = KeyGenerator.getInstance("DES").generateKey();
        cipher.init(Cipher.WRAP_MODE, secretKey);
        PublicKey publicKey = KeyPairGenerator.getInstance("DSA").generateKeyPair().getPublic();
        byte[] bytes = cipher.wrap(publicKey);
        cipher.init(Cipher.UNWRAP_MODE, secretKey);
        Key key = cipher.unwrap(bytes, "DSA", Cipher.PUBLIC_KEY);
        System.out.println(key);
    }

    @Test
    public void test28() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("DES");
        SecretKey secretKey = KeyGenerator.getInstance("DES").generateKey();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] bytes = cipher.doFinal("Hello world!!!".getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        System.out.println(new String(cipher.doFinal(bytes)));
    }

    @Test
    public void test27() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        SecretKey secretKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(KeyGenerator.getInstance("DES").generateKey().getEncoded()));
        System.out.println(secretKey);
    }

    @Test
    public void test26() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        KeyPair keyPair1 = keyPairGenerator.genKeyPair();
        KeyPair keyPair2 = keyPairGenerator.genKeyPair();
        keyAgreement.init(keyPair2.getPrivate());
        keyAgreement.doPhase(keyPair1.getPublic(), true);
        byte[] bytes = keyAgreement.generateSecret();
        System.out.println(Arrays.toString(bytes));
    }

    @Test
    public void test25() throws NoSuchAlgorithmException {
        System.out.println(KeyGenerator.getInstance("HmacMD5").generateKey());
    }

    @Test
    public void test24() throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(KeyGenerator.getInstance("HmacMD5").generateKey());
        byte[] bytes = mac.doFinal("123456".getBytes());
        System.out.printf("%032x", new BigInteger(1, bytes));
    }

    @Test
    public void test23() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream("C:\\Users\\Administrator\\.keystore"), "password".toCharArray());
        System.out.println(keyStore.getKey("mykey", "passwd".toCharArray()));
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", new KeyStore.PasswordProtection("passwd".toCharArray()));
        System.out.println(entry.getPrivateKey());
    }

    @Test
    public void test22() throws CertificateException, FileNotFoundException {
        CertPath certPath = CertificateFactory.getInstance("X509").generateCertPath(new FileInputStream("C:\\a.cer"));
        Timestamp timestamp = new Timestamp(new Date(), certPath);
        CodeSigner codeSigner = new CodeSigner(certPath, timestamp);
        System.out.println(codeSigner);
        System.out.println(codeSigner.equals(new CodeSigner(certPath, timestamp)));
    }

    @Test
    public void test21() throws CertificateException, FileNotFoundException {
        System.out.println(new Timestamp(new Date(), CertificateFactory.getInstance("X509").generateCertPath(new FileInputStream("C:\\a.cer"))));
    }

    @Test
    public void test20() throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        byte[] bytes = "Hello world!".getBytes();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Signature signature = Signature.getInstance("RSA");
        SignedObject signedObject = new SignedObject(bytes, keyPair.getPrivate(), signature);
        System.out.println(Arrays.toString(signedObject.getSignature()));
        System.out.println(signedObject.verify(keyPair.getPublic(), signature));
    }

    @Test
    public void test19() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance("RSA");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        signature.initSign(keyPair.getPrivate());
        byte[] bytes = "Hello World!!!".getBytes();
        signature.update(bytes);
        byte[] sign = signature.sign();
        signature.initVerify(keyPair.getPublic());
        signature.update(bytes);
        System.out.println(signature.verify(sign));
    }

    @Test
    public void test18() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(secretKey);
    }

    @Test
    public void test17() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyPairGenerator.generateKeyPair().getPrivate().getEncoded()));
        System.out.println(privateKey);
    }

    @Test
    public void test16() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        System.out.println(keyPair.getPrivate());
        System.out.println(keyPair.getPublic());
    }

    @Test
    public void test15() {
        byte[] array = ByteBuffer.allocate(4).putInt(150).array();
        System.out.println(Arrays.toString(array));
        System.out.println(Arrays.toString(new BigInteger("150", 10).toByteArray()));
        System.out.println(new BigInteger(1, array).intValue());
    }

    @Test
    public void test14() throws NoSuchAlgorithmException, IOException {
        //19048128919019788463925
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("DES");
        algorithmParameters.init(new BigInteger("19048128919019788463925").toByteArray());
        byte[] encoded = algorithmParameters.getEncoded();
        System.out.println(new BigInteger(1, encoded));
    }


    @Test
    public void test13() throws NoSuchAlgorithmException, IOException {
        AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("DES");
        algorithmParameterGenerator.init(56);
        AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
        byte[] encoded = algorithmParameters.getEncoded();
        System.out.println(new BigInteger(encoded));
    }

    @Test
    public void test12() {
        System.out.println(Security.getProperty("security.provider.11"));
        System.out.println(new BouncyCastleProvider().getName());
    }

    @Test
    public void test11() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        System.out.println(keyPair.getPrivate());
        System.out.println("************************************************");
        System.out.println(keyPair.getPublic());
    }

    @Test
    public void test10() {
        Security.getAlgorithms("Cipher").forEach(System.out::println);
    }

    @Test
    public void test9() throws NoSuchAlgorithmException, IOException {
        AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("DES");
        algorithmParameterGenerator.init(56);
        AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
        byte[] encoded = algorithmParameters.getEncoded();
        System.out.println(new BigInteger(encoded));
    }

    @Test
    public void test8() throws IOException, NoSuchAlgorithmException {
        System.out.printf("%040x%n", new BigInteger(1, MessageDigest.getInstance("SHA").digest(Files.readAllBytes(Paths.get("C:\\Users\\Administrator\\Downloads\\pcmastersetup_u3.exe")))));

        DigestOutputStream digestOutputStream = new DigestOutputStream(new ByteArrayOutputStream(), MessageDigest.getInstance("MD5"));
        digestOutputStream.write("123456".getBytes());
        System.out.printf("%032x%n", new BigInteger(1, digestOutputStream.getMessageDigest().digest()));

        byte[] bytes = "123456".getBytes(StandardCharsets.UTF_8);
        DigestInputStream digestInputStream = new DigestInputStream(new ByteArrayInputStream(bytes), MessageDigest.getInstance("MD5"));
        digestInputStream.read(bytes);
        System.out.printf("%032x%n", new BigInteger(1, digestInputStream.getMessageDigest().digest()));
    }

    @Test
    public void test7() throws IOException, NoSuchAlgorithmException {
        String path = "http://down.ruanmei.com/tweakcube/partner/pcmastersetup_u3.exe";
        DigestInputStream digestInputStream = new DigestInputStream(new URL(path).openStream(), MessageDigest.getInstance("SHA"));
        DigestOutputStream digestOutputStream = new DigestOutputStream(new FileOutputStream("C:\\a.exe"), MessageDigest.getInstance("SHA"));
        byte[] buffer = new byte[1024 * 1024];
        int len = 0;
        while ((len = digestInputStream.read(buffer)) != -1) {
            digestOutputStream.write(buffer, 0, len);
        }
        byte[] digest = digestOutputStream.getMessageDigest().digest();
        System.out.printf("%040X%n", new BigInteger(1, digest));
        System.out.println(MessageDigest.isEqual(digestInputStream.getMessageDigest().digest(), digest));
    }

    @Test
    public void test6() throws NoSuchAlgorithmException, IOException {
        byte[] bytes = "123456".getBytes(StandardCharsets.UTF_8);
        DigestInputStream digestInputStream = new DigestInputStream(new ByteArrayInputStream(bytes), MessageDigest.getInstance("MD5"));
        digestInputStream.read(bytes);
        System.out.printf("%032x%n", new BigInteger(1, digestInputStream.getMessageDigest().digest()));
        System.out.printf("%032x%n", new BigInteger(1, MessageDigest.getInstance("MD5").digest("123456".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    public void test5() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA");
        messageDigest.update("sha".getBytes());
        System.out.println(messageDigest.digest());
    }

    @Test
    public void test4() throws NoSuchAlgorithmException {
        System.out.println(MessageDigest.getInstance("MD5").toString());
    }

    @Test
    public void test3() throws NoSuchAlgorithmException {
        System.out.println(MessageDigest.getInstance("Md5").getAlgorithm());
        System.out.println(MessageDigest.getInstance("MD5").getAlgorithm());
        Provider provider = MessageDigest.getInstance("MD5").getProvider();
        System.out.println(provider);
        for (Map.Entry<Object, Object> entry : provider.entrySet()) {
            System.out.println(entry.getKey());
        }

    }

    @Test
    public void test2() throws NoSuchAlgorithmException {
        System.out.println(MessageDigest.getInstance("MD5").getDigestLength());
        System.out.println(MessageDigest.getInstance("SHA").getDigestLength());
        System.out.println(MessageDigest.getInstance("SHA-1").digest("123456".getBytes(StandardCharsets.UTF_8)).length);
        System.out.printf("%040x", new BigInteger(1, MessageDigest.getInstance("SHA-1").digest("123456".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    public void test() {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            System.out.println(provider);
        }
    }
}