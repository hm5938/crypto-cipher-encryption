package com.example.crypto_cipher_encryption;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 암호화에 사용할 키, 디폴트로 128bit(16Byte)
        String encryptionKey = "encryptionkey!!!";

        // 암호화할 문자열
        String target = "AES/RSA 암호화를 해보아요";


        // AES로 암호화 =================================================
        Cipher cipher = null;
        try {
            // AES Cipher 객체 생성
            cipher = Cipher.getInstance("AES");
            // 암호화 Chipher 초기화
            SecretKeySpec secretKeySpec = new SecretKeySpec(encryptionKey.getBytes(),"AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            // 암호화 완료
            byte[] encryptBytes = cipher.doFinal(target.getBytes("UTF-8"));
            System.out.println(new String(encryptBytes)); // => 똑같은 암호화키로 복호화

            // AES로 복호화 =================================================

            // 복호화 Chipher 초기화, 똑같은 암호화키로 복호화
            cipher.init(cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decryptBytes = cipher.doFinal(encryptBytes);
            System.out.println(new String(decryptBytes, "UTF-8"));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        // RSA 로 암호화 =================================================
        cipher = null;
        KeyPairGenerator keypairgen = null;
        try {
            // RSA 비밀키와 공개키를 생성
            keypairgen = KeyPairGenerator.getInstance("RSA");
            KeyPair keyPair = keypairgen.generateKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            // Cipher 객체 생성과 비밀키 초기화
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);

            // 암호화 완료
            byte[] encryptBytes = cipher.doFinal(target.getBytes());
            System.out.println(new String(encryptBytes)); // => 암호화되어 읽지못함

            // RSA로 복호화 =================================================

            // 복호화 Chipher 초기화, 비밀키와 쌍인 공개키로 복호화함.
            cipher.init(cipher.DECRYPT_MODE, publicKey);
            byte[] decryptBytes = cipher.doFinal(encryptBytes);
            System.out.println(new String(decryptBytes));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

    }
}