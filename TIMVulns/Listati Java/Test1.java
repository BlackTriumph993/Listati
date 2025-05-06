import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.*;
import java.util.Base64;

public class VulnerableCode {

    public static void main(String[] args) throws Exception {

        String username = args[0];
        String password = args[1];
        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/mydb", "user", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);


        String serializedObject = args[2];
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(serializedObject)));
        ois.readObject();


        String url = args[3];
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("GET");
        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        System.out.println(response.toString());

        // Iniezione di comandi (CVSS 3.1: 9.8 - Critico)
        String command = args[4];
        Runtime.getRuntime().exec(command);
    }
}
