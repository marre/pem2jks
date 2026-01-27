import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.Key;
import java.util.Enumeration;

public class VerifyKeystore {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: java VerifyKeystore <keystore> <password> [type]");
            System.err.println("  type: JKS (default) or PKCS12");
            System.exit(1);
        }

        String keystorePath = args[0];
        String password = args[1];
        
        // Determine keystore type from argument, system property, or file extension
        String keystoreType = "JKS";
        if (args.length >= 3) {
            keystoreType = args[2];
        } else if (System.getProperty("keystore.type") != null) {
            keystoreType = System.getProperty("keystore.type");
        } else if (keystorePath.toLowerCase().endsWith(".p12") || 
                   keystorePath.toLowerCase().endsWith(".pfx")) {
            keystoreType = "PKCS12";
        }

        System.out.println("Loading keystore: " + keystorePath);

        KeyStore ks = KeyStore.getInstance(keystoreType);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password.toCharArray());
        }

        System.out.println("Keystore loaded successfully!");
        System.out.println("Keystore type: " + ks.getType());
        System.out.println("Entry count: " + ks.size());
        System.out.println();

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);

            if (ks.isKeyEntry(alias)) {
                System.out.println("  Type: Private Key Entry");
                try {
                    Key key = ks.getKey(alias, password.toCharArray());
                    System.out.println("  Key Algorithm: " + key.getAlgorithm());
                    System.out.println("  Key Format: " + key.getFormat());
                } catch (Exception e) {
                    System.out.println("  Key: (failed to load: " + e.getMessage() + ")");
                }
                
                Certificate[] chain = ks.getCertificateChain(alias);
                if (chain != null) {
                    System.out.println("  Certificate Chain Length: " + chain.length);
                    for (int i = 0; i < chain.length; i++) {
                        System.out.println("    [" + i + "] " + chain[i].getType());
                    }
                }
            } else if (ks.isCertificateEntry(alias)) {
                System.out.println("  Type: Trusted Certificate Entry");
                Certificate cert = ks.getCertificate(alias);
                System.out.println("  Certificate Type: " + cert.getType());
            }
            System.out.println();
        }

        System.out.println("Verification complete - keystore is valid!");
    }
}
