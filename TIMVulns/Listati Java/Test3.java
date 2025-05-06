import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;

public class AdvancedVulnerableCode {

    public static void main(String[] args) throws Exception {
        HttpServletRequest request = // ... (ottenere la richiesta HTTP) ...
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("serializedObject")) {
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(cookie.getValue())));
                ois.readObject();
            }
        }


        String filePath = args[0];
        if (filePath.contains("..")) {
            throw new IllegalArgumentException("Path traversal detected");
        }
        String fileContent = new String(Files.readAllBytes(Paths.get(filePath)));
        Runtime.getRuntime().exec(fileContent);


        String encryptedData = args[1];
        String key = "mysecretkey"; // Chiave hardcoded
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        System.out.println(new String(decryptedBytes));


        String password = args[2];
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        byte[] digest = md.digest();
        System.out.println(Base64.getEncoder().encodeToString(digest));
    }
}
