package certificate;

import java.io.FileWriter;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import bls.BLS;
import cn.hutool.core.io.FileUtil;
import it.unisa.dia.gas.jpbc.Element;

public class CertificateUtils {
    /**
     * 生成密钥对及证书
     * 
     * @param certificateInfo 证书信息
     * @param caPrivateKey    根证书私钥，用于给证书签名
     * @return
     * @throws Throwable
     */
    public static KeyAndCertificate generateRootCertificate(CertificateInfo certificateInfo)
            throws Throwable {
        // 生成证书所需密钥对，BLS 算法
        Element sk = BLS.GeneratePrivateKey();
        Element pk = BLS.GeneratePublicKey(sk);

        // 构建证书主题和颁发者
        X500Name issuer = certificateInfo.getIssuer();
        X500Name subject = certificateInfo.getSubject();

        // BLSPublicKey blsPublicKey = new BLSPublicKey(pk);
        SubjectPublicKeyInfo subjectPublicKeyInfo = BLS.encodePublicKey(pk);

        // 构建证书
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                certificateInfo.getSerial(),
                certificateInfo.getNotBefore(),
                certificateInfo.getNotAfter(),
                subject,
                subjectPublicKeyInfo);
        // certBuilder.addExtension(Extension.basicConstraints, true, new
        // BasicConstraints(true));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // 使用 BLS 签名器
        BLSContentSigner signer = new BLSContentSigner(sk);
        // 生成证书
        X509CertificateHolder certHolder = certBuilder.build(signer);
        // 转换为 X509Certificate
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

        return new KeyAndCertificate(sk, pk, cert);
    }

    /**
     * 生成密钥对及证书
     * 
     * @param certificateInfo 证书信息
     * @param caPrivateKey    根证书私钥，用于给证书签名
     * @return
     * @throws Throwable
     */
    public static KeyAndCertificate generateCertificate(CertificateInfo certificateInfo, Element caPrivateKey)
            throws Throwable {
        // 生成证书所需密钥对，BLS 算法
        Element sk = BLS.GeneratePrivateKey();
        Element pk = BLS.GeneratePublicKey(sk);

        // 构建证书主题和颁发者
        X500Name issuer = certificateInfo.getIssuer();
        X500Name subject = certificateInfo.getSubject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = BLS.encodePublicKey(pk);
        // 构建证书
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                certificateInfo.getSerial(),
                certificateInfo.getNotBefore(),
                certificateInfo.getNotAfter(),
                subject,
                subjectPublicKeyInfo);
        // certBuilder.addExtension(
        // Extension.keyUsage,
        // true,
        // new KeyUsage(KeyUsage.digitalSignature) // 允许数字签名
        // );
        // 添加 BasicConstraints 扩展
        if (certificateInfo.isCA()) {
            certBuilder.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(certificateInfo.getPathLenConstraint()));
        }
        // 设置 KeyUsage 为允许证书签名
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        // 使用 BLS 签名器
        BLSContentSigner signer = new BLSContentSigner((caPrivateKey != null) ? caPrivateKey : sk);

        // 生成证书
        X509CertificateHolder certHolder = certBuilder.build(signer);
        // 转换为 X509Certificate
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

        return new KeyAndCertificate(sk, pk, cert);
    }

    /**
     * 保存私钥到磁盘
     * 
     * @param privateKey
     * @param filePath
     * @throws Throwable
     */
    public static void saveprivatekey(Element privateKey, String filePath) throws Throwable {
        save(privateKey.toBytes(), X509CertificateConstants.PRIVATE_KEY_TYPE, filePath);
    }

    /**
     * 保存公钥到磁盘
     * 
     * @param publicKey
     * @param filePath
     * @throws Throwable
     */
    public static void savepublicKey(Element publicKey, String filePath) throws Throwable {
        save(publicKey.toBytes(), X509CertificateConstants.PUBLIC_KEY_TYPE, filePath);
    }

    /**
     * 保存证书到磁盘
     * 
     * @param certificate
     * @param filePath
     * @throws Throwable
     */
    public static void save(Certificate certificate, String filePath) throws Throwable {
        save(certificate.getEncoded(), X509CertificateConstants.CERTIFICATE_TYPE, filePath);
    }

    /**
     * 以 PEM 格式保存密钥、证书到磁盘
     * 
     * @param encodedBytes
     * @param type
     * @param filePath
     * @throws Throwable
     */
    public static void save(byte[] encodedBytes, String type, String filePath) throws Throwable {
        FileUtil.mkParentDirs(filePath);
        PemObject pemObject = new PemObject(type, encodedBytes);
        try (FileWriter fileWriter = new FileWriter(filePath); PemWriter pemWriter = new PemWriter(fileWriter)) {
            pemWriter.writeObject(pemObject);
        }
    }
}
