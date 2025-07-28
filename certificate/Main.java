package certificate;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import bls.BLS;
import cn.hutool.core.date.DateField;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.RandomUtil;
import it.unisa.dia.gas.jpbc.Element;

public class Main {
    /**
     * 自签名根证书私钥保存路径
     */
    private static final String CA_PRIVATE_KEY_FILE_PATH = "cert/root/root_sk.key";
    /**
     * 自签名根证书公钥保存路径
     */
    private static final String CA_PUBLIC_KEY_FILE_PATH = "cert/root/root_pk.key";
    /**
     * 自签名根证书保存路径
     */
    private static final String CA_CERTIFICATE_FILE_PATH = "cert/root/root_ca.cer";

    /*
     * 中间私钥
     */
    private static final String CA_INTERMIDEA_PRIVATE_KEY_FILE_PATH = "cert/org/node/node_sk.key";
    /*
     * 中间公钥
     */
    private static final String CA_INTERMIDEA_PUBLIC_KEY_FILE_PATH = "cert/org/node/node_pk.key";
    /*
     * 中间证书
     */
    private static final String CA_INTERMIDEA_CERTIFICATE_FILE_PATH = "cert/org/node/node_cert.cer";

    /**
     * 自签名证书私钥保存路径
     */
    private static final String SELF_SIGNED_PRIVATE_KEY_FILE_PATH = "cert/node/node10/node_sk.key";
    /**
     * 自签名证书公钥保存路径
     */
    // private static final String SELF_SIGNED_PUBLIC_KEY_FILE_PATH =
    // "cert/node/node1/node_pk.key";
    /**
     * 自签名证书保存路径
     */
    private static final String SELF_SIGNED_CERTIFICATE_FILE_PATH = "cert/node/node10/node.cer";

    /**
     * 生成根证书及其密钥对
     * 
     * @throws Throwable
     */
    public static void generateCaCertificate() throws Throwable {
        // 根证书主题信息
        X500Name subject = new SubjectBuilder()
                .setCn("root.example.com")
                .setO("example.com")
                .setOu("root")
                .setC("CN")
                .setSt("GuangXi")
                .setL("GuiLin")
                .build();

        // 根证书颁发者信息，即自身
        X500Name issuer = subject;

        // 根证书有效期
        DateTime notBefore = DateUtil.yesterday();
        DateTime notAfter = DateUtil.offset(notBefore, DateField.YEAR, 10);

        CertificateInfo certificateInfo = new CertificateInfo();
        certificateInfo.setSerial(BigInteger.valueOf(RandomUtil.randomLong(1L, Long.MAX_VALUE)));
        certificateInfo.setIssuer(issuer);
        certificateInfo.setSubject(subject);
        certificateInfo.setNotBefore(notBefore);
        certificateInfo.setNotAfter(notAfter);
        certificateInfo.setKeyAlgorithm(X509CertificateConstants.KEY_ALGORITHM);
        certificateInfo.setSignAlgorithm(X509CertificateConstants.SIGN_ALGORITHM);
        certificateInfo.setPathLenConstraint(1);
        // 生成根证书及其密钥对
        KeyAndCertificate keyAndCertificate = CertificateUtils.generateRootCertificate(certificateInfo);
        // 保存根证书及其密钥对到磁盘
        CertificateUtils.saveprivatekey(keyAndCertificate.getPrivateKey(), CA_PRIVATE_KEY_FILE_PATH);
        CertificateUtils.savepublicKey(keyAndCertificate.getPublicKey(), CA_PUBLIC_KEY_FILE_PATH);
        CertificateUtils.save(keyAndCertificate.getX509Certificate(), CA_CERTIFICATE_FILE_PATH);
    }

    static {
        // 添加Bouncy Castle安全提供者
        Security.addProvider(new BouncyCastleProvider());
        // 注册自定义的CertPathValidator
        Security.addProvider(new BLSCertPathValidatorProvider());
    }

    // 自定义CertPathValidator的Provider
    public static class BLSCertPathValidatorProvider extends java.security.Provider {
        public BLSCertPathValidatorProvider() {
            super("BLSValidator", 1.0, "BLS CertPathValidator Provider");
            put("CertPathValidator.PKIX", BLSCertPathValidator.class.getName());
        }
    }

    public static X509Certificate parseCertificate(String certificateFilePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(certificateFilePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    /**
     * 生成证书及其密钥对
     * 
     * @throws Throwable
     */
    public static void generateSelfSignedCertificate() throws Throwable {
        // 根证书私钥
        Element sk = null;
        // 从磁盘加载根证书私钥
        try (FileInputStream fileInputStream = new FileInputStream(CA_PRIVATE_KEY_FILE_PATH);) {
            sk = BLS.PemToSk(fileInputStream);
        }

        // 从磁盘加载根证书
        X509Certificate caCertificate = parseCertificate(CA_CERTIFICATE_FILE_PATH);

        // 证书颁发者信息
        X500Name issuer = new X500Name(caCertificate.getSubjectX500Principal().getName());

        // 证书主题信息
        X500Name subject = new SubjectBuilder()
                .setL("GuiLin")
                .setSt("GuangXi")
                .setC("CN")
                .setOu("node")
                .setO("example.com")
                .setCn("node.example.com")
                .build();

        // 证书有效期
        DateTime notBefore = DateUtil.yesterday();
        DateTime notAfter = DateUtil.offset(notBefore, DateField.YEAR, 10);

        CertificateInfo certificateInfo = new CertificateInfo();
        certificateInfo.setSerial(BigInteger.valueOf(RandomUtil.randomLong(1L,
                Long.MAX_VALUE)));
        certificateInfo.setIssuer(issuer);
        certificateInfo.setSubject(subject);
        certificateInfo.setNotBefore(notBefore);
        certificateInfo.setNotAfter(notAfter);

        certificateInfo.setKeyAlgorithm(X509CertificateConstants.KEY_ALGORITHM);
        certificateInfo.setSignAlgorithm(X509CertificateConstants.SIGN_ALGORITHM);
        certificateInfo.setCA(true);
        certificateInfo.setPathLenConstraint(0);// 不允许中间CA
        // 生成自签名证书及其密钥对
        KeyAndCertificate keyAndCertificate = CertificateUtils.generateCertificate(certificateInfo,
                sk);

        // 保存自签名证书及其密钥对到磁盘
        CertificateUtils.saveprivatekey(keyAndCertificate.getPrivateKey(),
                CA_INTERMIDEA_PRIVATE_KEY_FILE_PATH);
        // CertificateUtils.savepublicKey(keyAndCertificate.getPublicKey(),
        // CA_INTERMIDEA_PUBLIC_KEY_FILE_PATH);
        CertificateUtils.save(keyAndCertificate.getX509Certificate(),
                CA_INTERMIDEA_CERTIFICATE_FILE_PATH);
    }

    /**
     * 生成终端证书及其密钥对
     * 
     * @throws Throwable
     */
    public static void generateEndSignedCertificate() throws Throwable {
        // 根证书私钥
        Element sk = null;
        // 从磁盘加载根证书私钥
        try (FileInputStream fileInputStream = new FileInputStream(CA_INTERMIDEA_PRIVATE_KEY_FILE_PATH);) {
            sk = BLS.PemToSk(fileInputStream);
        }

        // 从磁盘加载中间证书
        X509Certificate interCertificate = parseCertificate(CA_INTERMIDEA_CERTIFICATE_FILE_PATH);

        // 证书颁发者信息
        X500Name issuer = new X500Name(interCertificate.getSubjectX500Principal().getName());

        // 证书主题信息
        X500Name subject = new SubjectBuilder()
                .setL("GuiLin")
                .setSt("GuangXi")
                .setC("CN")
                .setOu("node10")
                .setO("example.com")
                .setCn("node10.example.com")
                .build();

        // 证书有效期
        DateTime notBefore = DateUtil.yesterday();
        DateTime notAfter = DateUtil.offset(notBefore, DateField.YEAR, 10);

        CertificateInfo certificateInfo = new CertificateInfo();
        certificateInfo.setSerial(BigInteger.valueOf(RandomUtil.randomLong(1L,
                Long.MAX_VALUE)));
        certificateInfo.setIssuer(issuer);
        certificateInfo.setSubject(subject);
        certificateInfo.setNotBefore(notBefore);
        certificateInfo.setNotAfter(notAfter);
        certificateInfo.setKeyAlgorithm(X509CertificateConstants.KEY_ALGORITHM);
        certificateInfo.setSignAlgorithm(X509CertificateConstants.SIGN_ALGORITHM);
        certificateInfo.setCA(false);
        // 生成自签名证书及其密钥对
        KeyAndCertificate keyAndCertificate = CertificateUtils.generateCertificate(certificateInfo,
                sk);
        // 保存自签名证书及其密钥对到磁盘
        CertificateUtils.saveprivatekey(keyAndCertificate.getPrivateKey(),
                SELF_SIGNED_PRIVATE_KEY_FILE_PATH);
        // CertificateUtils.savepublicKey(keyAndCertificate.getPublicKey(),
        // SELF_SIGNED_PUBLIC_KEY_FILE_PATH);
        CertificateUtils.save(keyAndCertificate.getX509Certificate(),
                SELF_SIGNED_CERTIFICATE_FILE_PATH);
    }

    public static boolean verifyCertificate() {
        try {
            // 从磁盘加载证书
            X509Certificate clientCertificate = parseCertificate(SELF_SIGNED_CERTIFICATE_FILE_PATH);

            String root = Util.readCertificateFile(CA_INTERMIDEA_CERTIFICATE_FILE_PATH);

            // 从字符串加载证书
            X509Certificate rootCertificate = Util.parseCertificate1(root);
            // 提取证书中的公钥
            Element root_pk = BLS.decodePublicKey(rootCertificate.getPublicKey().getEncoded());
            // Element client_pk =
            // BLS.decodePublicKey(clientCertificate.getPublicKey().getEncoded());

            // 获取 DER 编码的 TBS 数据（直接使用字节数组，不转为字符串）
            byte[] tbsData = clientCertificate.getTBSCertificate();
            // 提取证书签名并解码 DER Octet String
            byte[] signature = clientCertificate.getSignature();
            ASN1InputStream asn = new ASN1InputStream(signature);
            ASN1Primitive asn1 = asn.readObject();
            byte[] sigBytes = ((DEROctetString) asn1).getOctets(); // 提取原始签名字节
            Element sig = BLS.PemToSig(sigBytes); // 使用 BLS 库方法解码
            asn.close();
            return BLS.verify(sig, root_pk, new String(tbsData));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean verifyChain() throws Throwable {
        // 从磁盘加载根证书
        X509Certificate caCertificate = parseCertificate(CA_CERTIFICATE_FILE_PATH);
        X509Certificate interCertificate = parseCertificate(CA_INTERMIDEA_CERTIFICATE_FILE_PATH);
        X509Certificate endCert = parseCertificate(SELF_SIGNED_CERTIFICATE_FILE_PATH);

        // 将 X500Principal 转换为 X500Name
        X500Name caIssuser = new X500Name(caCertificate.getIssuerX500Principal().getName());
        X500Name caSubject = new X500Name(caCertificate.getSubjectX500Principal().getName());
        X500Name intermediateIssuer = new X500Name(interCertificate.getIssuerX500Principal().getName());
        X500Name intermediateSubject = new X500Name(interCertificate.getSubjectX500Principal().getName());
        X500Name endEntityIssuer = new X500Name(endCert.getIssuerX500Principal().getName());
        X500Name endEntitySubject = new X500Name(endCert.getSubjectX500Principal().getName());

        // 调试输出：打印颁发者和主题
        System.out.println("[根证书] Subject: " +
                caCertificate.getSubjectX500Principal().getName());
        System.out.println("[中间证书] Issuer: " +
                interCertificate.getIssuerX500Principal().getName());
        System.out.println("[中间证书] Subject: " +
                interCertificate.getSubjectX500Principal());
        System.out.println("[终端证书] Issuer: " +
                endCert.getIssuerX500Principal());
        System.out.println("[终端证书] Subject: " +
                endCert.getSubjectX500Principal());

        System.out.println(intermediateSubject.equals(endEntityIssuer));
        System.out.println(caSubject.equals(intermediateIssuer));
        // // 验证中间证书的颁发者是否等于根证书的主题
        // if
        // (!interCertificate.getIssuerX500Principal().equals(caCertificate.getSubjectX500Principal()))
        // {
        // throw new SecurityException("中间证书的颁发者与根证书主题不匹配！");
        // }

        // // 验证终端证书的颁发者是否等于中间证书的主题
        // if
        // (!endCert.getIssuerX500Principal().equals(interCertificate.getSubjectX500Principal()))
        // {
        // throw new SecurityException("终端证书的颁发者与中间证书主题不匹配！");
        // }

        List<X509Certificate> certChain = Arrays.asList(endCert, interCertificate);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath certPath = factory.generateCertPath(certChain);
        // 根证书作为信任锚，不加入链中

        PKIXParameters parameters = new PKIXParameters(
                Collections.singleton(new TrustAnchor(caCertificate, null)));
        parameters.setRevocationEnabled(false); // 禁用CRL检查（如有需要可启用）
        // 获取自定义验证器
        parameters.setDate(new Date()); // 启用有效期检查
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BLSValidator");
        validator.validate(certPath, parameters);
        return true;
    }

    public static void main(String[] args) {
        // // 生成根证书
        // try {
        // generateCaCertificate();
        // } catch (Throwable t) {
        // t.printStackTrace();
        // }
        // 中间证书
        // try {
        //     generateSelfSignedCertificate();
        // } catch (Throwable t) {
        //     t.printStackTrace();
        // }
        // 终端证书
        try {
            generateEndSignedCertificate();// 生成终端证书
        } catch (Throwable t) {
            t.printStackTrace();
        }
        // 验证证书
        try {
            System.out.println(verifyCertificate());
        } catch (Exception e) {
            e.printStackTrace();
        }
        // 验证证书链
        try {
            verifyChain();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}
