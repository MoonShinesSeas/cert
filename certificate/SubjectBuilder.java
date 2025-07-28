package certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import cn.hutool.core.util.StrUtil;

public class SubjectBuilder {
    /**
     * 常用名称（Common Name）
     */
    private String cn;
    /**
     * 部门（Organizational Unit）
     */
    private String ou;
    /**
     * 企业名称（Organization）
     */
    private String o;
    /**
     * 城市（Locality）
     */
    private String l;
    /**
     * 省份（State）
     */
    private String st;
    /**
     * 国家（Country）
     */
    private String c;

    public SubjectBuilder setCn(String cn) {
        this.cn = cn;
        return this;
    }

    public SubjectBuilder setO(String o) {
        this.o = o;
        return this;
    }

    public SubjectBuilder setOu(String ou) {
        this.ou = ou;
        return this;
    }

    public SubjectBuilder setC(String c) {
        this.c = c;
        return this;
    }

    public SubjectBuilder setSt(String st) {
        this.st = st;
        return this;
    }

    public SubjectBuilder setL(String l) {
        this.l = l;
        return this;
    }

    public X500Name build() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        if (StrUtil.isNotBlank(cn)) {
            x500NameBuilder.addRDN(BCStyle.CN, cn);
        }
        if (StrUtil.isNotBlank(ou)) {
            x500NameBuilder.addRDN(BCStyle.OU, ou);
        }
        if (StrUtil.isNotBlank(o)) {
            x500NameBuilder.addRDN(BCStyle.O, o);
        }
        if (StrUtil.isNotBlank(l)) {
            x500NameBuilder.addRDN(BCStyle.L, l);
        }
        if (StrUtil.isNotBlank(st)) {
            x500NameBuilder.addRDN(BCStyle.ST, st);
        }
        if (StrUtil.isNotBlank(c)) {
            x500NameBuilder.addRDN(BCStyle.C, c);
        }
        

        return x500NameBuilder.build();
    }
}