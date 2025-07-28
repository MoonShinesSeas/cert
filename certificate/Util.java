package certificate;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import bls.BLS;
import it.unisa.dia.gas.jpbc.Element;

public class Util {
    public static X509Certificate parseCertificate(String certificateFilePath) {
        try (FileInputStream fis = new FileInputStream(certificateFilePath)) {
            System.out.println(fis);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static X509Certificate parseCertificate1(String certificateContent) {
        try (InputStream is = new ByteArrayInputStream(certificateContent.getBytes())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(is);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String readCertificateFile(String filePath) {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append(System.lineSeparator()); // 保留换行符
            }
            // 移除最后一个多余的换行符（如果有的话）
            if (content.length() > 0) {
                content.deleteCharAt(content.length() - 1);
            }
        } catch (IOException e) {
            throw new RuntimeException("读取证书文件失败", e);
        }
        return content.toString();
    }

    /**
     * 读取密钥
     * 
     */
    public static Element readPrivateKey(String filePath) {
        // 从磁盘加载根证书私钥
        try (FileInputStream fileInputStream = new FileInputStream(filePath)) {
            return BLS.PemToSk(fileInputStream);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
