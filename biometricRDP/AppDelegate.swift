import AppKit
import Security
import CommonCrypto

final class AppDelegate: NSObject, NSApplicationDelegate {
    static var shared: AppDelegate?

    var appController: AppController!
    var testAPIServer: TestAPIServer?
    var mockController: MockController?
    var tlsIdentity: sec_identity_t?

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppDelegate.shared = self

        appController = AppController()
        appController.registerRoutes(on: TestAPIRouter.shared)

        let wc = WindowController()
        appController.windowController = wc

        let window = RDPWindow(contentRect: NSRect(x: 100, y: 100, width: 1280, height: 800),
                               styleMask: [.titled, .closable, .miniaturizable, .resizable],
                               backing: .buffered,
                               defer: false)
        window.title = "biometricRDP"
        window.contentViewController = wc
        // Force view load so WindowController.viewDidLoad registers window + session routes
        _ = wc.view
        window.makeKeyAndOrderFront(nil)
        wc.rdpWindow = window

        // Generate TLS identity for the mock RDP host after the app has fully launched.
        if ProcessInfo.processInfo.environment["BIOMETRICRDP_TEST_API"] == "1" {
            // Load TLS identity on main thread (SecPKCS12Import hangs on background threads)
            tlsIdentity = Self.loadEmbeddedTLSIdentity()
            if tlsIdentity == nil {
                NSLog("AppDelegate: WARNING - failed to load TLS identity, mock host will not work")
            }

            // Register mock controller routes BEFORE starting the test API server
            // so that /mock/* routes are available when the port file is written.
            let mc = MockController()
            _ = mc.view
            mc.sessionController = wc.sessionController
            mockController = mc

            // Register profiles controller for test-mode profiles dir
            let pc = ProfilesController()
            _ = pc.view

            do {
                let server = TestAPIServer()
                try server.start()
                testAPIServer = server
            } catch {
                NSLog("Failed to start TestAPIServer: \(error)")
            }
        }

        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }

    // MARK: - Self-signed TLS identity generation

    private static func generateSelfSignedIdentity() -> sec_identity_t? {
        // 1. Generate RSA key pair
        var keyErr: Unmanaged<CFError>?
        guard let privKey = SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ] as CFDictionary, &keyErr) else {
            return nil
        }

        // 2. Get public key in DER format
        guard let pubKey = SecKeyCopyPublicKey(privKey),
              let pubKeyDER = SecKeyCopyExternalRepresentation(pubKey, &keyErr) as Data? else {
            return nil
        }

        // 3. Build self-signed X.509v3 certificate DER
        guard let certDER = buildSelfSignedCertDER(publicKeyDER: pubKeyDER, privateKey: privKey) else {
            return nil
        }

        // 4. Create SecCertificate
        guard let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            return nil
        }

        // 5. Store cert and key in keychain, then create SecIdentity
        let label = "com.bimboware.biometricrdp.mock-tls" as CFString

        // Delete any previous entries
        SecItemDelete([kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: label] as CFDictionary)
        SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrLabel as String: label] as CFDictionary)

        // Add certificate
        let certStatus = SecItemAdd([
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: cert,
            kSecAttrLabel as String: label
        ] as CFDictionary, nil)
        guard certStatus == errSecSuccess else {
            return nil
        }

        // Add private key
        let keyStatus = SecItemAdd([
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: privKey,
            kSecAttrLabel as String: label
        ] as CFDictionary, nil)
        guard keyStatus == errSecSuccess else {
            return nil
        }

        // 6. Query the identity (cert + key pair auto-associated in keychain)
        let idStatus = SecItemCopyMatching([
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true
        ] as CFDictionary, nil)

        // If no identity found, try querying by certificate
        if idStatus != errSecSuccess {
            var certRef: CFTypeRef?
            let certStatus2 = SecItemCopyMatching([
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: label,
                kSecReturnRef as String: true
            ] as CFDictionary, &certRef)
            if certStatus2 == errSecSuccess, let foundCert = certRef {
                // Use the private key we already stored: SecIdentity should auto-associate
                // when both cert and key are in the keychain
            }
            return nil
        }

        // idStatus was success, but we need the result — query again
        var idResult: CFTypeRef?
        let finalStatus = SecItemCopyMatching([
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true
        ] as CFDictionary, &idResult)

        if finalStatus == errSecSuccess, let identityRef = idResult {
            return sec_identity_create((identityRef as! SecIdentity))
        }

        return nil
    }

    // MARK: - Embedded TLS identity (PKCS#12)

    /// Embedded self-signed PKCS#12 identity (password: "mock").
    /// Generated at build time. SecPKCS12Import hangs on background threads,
    /// so this must be loaded on the main thread during app launch.

    private static func loadEmbeddedTLSIdentity() -> sec_identity_t? {
        guard let p12Data = Data(base64Encoded: mockP12Base64) else {
            NSLog("AppDelegate: PKCS#12 base64 decode failed")
            return nil
        }
        let options: [String: String] = [kSecImportExportPassphrase as String: "mock"]
        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess, let arr = items as? [[String: Any]] else {
            NSLog("AppDelegate: PKCS#12 import failed: \(status)")
            return nil
        }
        guard let first = arr.first, let identity = first[kSecImportItemIdentity as String] else {
            NSLog("AppDelegate: no identity in PKCS#12 items")
            return nil
        }
        return sec_identity_create(identity as! SecIdentity)
    }

    /// Base64-encoded PKCS#12 identity for mock TLS (password: "mock").
    /// Loaded by loadEmbeddedTLSIdentity() above on the main thread.
    private static let mockP12Base64 = "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"
    /// Build minimal DER-encoded self-signed X.509v3 certificate with SHA-1+RSA signature.
    private static func buildSelfSignedCertDER(publicKeyDER: Data, privateKey: SecKey) -> Data? {
        // DER helpers
        func derTag(_ tag: UInt8, content: Data) -> Data {
            var r = Data([tag]); r.append(derLen(content.count)); r.append(content); return r
        }
        func derLen(_ n: Int) -> Data {
            if n < 128 { return Data([UInt8(n)]) }
            if n < 256 { return Data([0x81, UInt8(n)]) }
            return Data([0x82, UInt8((n>>8)&0xFF), UInt8(n&0xFF)])
        }
        func derINT(_ v: Int) -> Data {
            if v == 0 { return Data([0x02,0x01,0x00]) }
            var b: [UInt8] = []; var x = v
            while x > 0 { b.append(UInt8(x&0xFF)); x >>= 8 }
            b.reverse()
            if b[0] & 0x80 != 0 { b.insert(0x00, at: 0) }
            return derTag(0x02, content: Data(b))
        }
        func derOID(_ oid: [UInt8]) -> Data { derTag(0x06, content: Data(oid)) }
        func derOIDSeq(_ bytes: [UInt8]) -> Data { derTag(0x30, content: derOID(bytes) + Data([0x05,0x00])) }
        func derCN(_ cn: String) -> Data {
            let cnB = Array(cn.utf8)
            let atv = derTag(0x30, content: derOID([0x55,0x04,0x03]) + derTag(0x13, content: Data(cnB)))
            return derTag(0x31, content: atv)
        }

        let version = derTag(0xa0, content: derINT(2))
        let serial  = derINT(1)
        let sigAlg  = derOIDSeq([0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05]) // sha1WithRSA
        let name    = derCN("biometricRDP-mock")

        let fmt = DateFormatter()
        fmt.dateFormat = "yyMMddHHmmss'Z'"; fmt.timeZone = TimeZone(identifier: "UTC")
        let nb = Array(fmt.string(from: Date()).utf8)
        let na = Array(fmt.string(from: Date().addingTimeInterval(86400)).utf8)
        let validity = derTag(0x30, content: derTag(0x17, content: Data(nb)) + derTag(0x17, content: Data(na)))

        // SPKI
        let rsaAlg = derOIDSeq([0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01]) // rsaEncryption
        let pubBits: Data = {
            let l = publicKeyDER.count + 1
            if l < 128 { return Data([0x03, UInt8(l), 0x00]) + publicKeyDER }
            if l < 256 { return Data([0x03, 0x81, UInt8(l), 0x00]) + publicKeyDER }
            return Data([0x03, 0x82, UInt8((l >> 8) & 0xFF), UInt8(l & 0xFF), 0x00]) + publicKeyDER
        }()
        let spki = derTag(0x30, content: rsaAlg + pubBits)

        // Extensions (empty SEQUENCE, tag [3])
        let extensions = Data([0xa3, 0x02, 0x30, 0x00])

        let tbsContent = version + serial + sigAlg + name + validity + name + spki + extensions
        let tbsLen = tbsContent.count
        let tbs: Data = {
            if tbsLen < 128 { return Data([0x30,UInt8(tbsLen)]) + tbsContent }
            if tbsLen < 256 { return Data([0x30,0x81,UInt8(tbsLen)]) + tbsContent }
            return Data([0x30,0x82,UInt8((tbsLen>>8)&0xFF),UInt8(tbsLen&0xFF)]) + tbsContent
        }()

        // Sign TBS with SHA-1 + RSA
        var sha1 = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        tbs.withUnsafeBytes { CC_SHA1($0.baseAddress, CC_LONG(tbs.count), &sha1) }

        // DigestInfo for SHA-1
        let sha1OID: [UInt8] = [0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a]
        let algId  = derTag(0x30, content: derOID(sha1OID) + Data([0x05,0x00]))
        let digOct = derTag(0x04, content: Data(sha1))
        let digestInfo = derTag(0x30, content: algId + digOct)

        var signErr: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey, .rsaSignatureMessagePKCS1v15SHA1, digestInfo as CFData, &signErr
        ) as Data? else {
            return nil
        }

        let sigBits: Data = {
            let l = signature.count + 1
            if l < 128 { return Data([0x03, UInt8(l), 0x00]) + signature }
            if l < 256 { return Data([0x03, 0x81, UInt8(l), 0x00]) + signature }
            return Data([0x03, 0x82, UInt8((l >> 8) & 0xFF), UInt8(l & 0xFF), 0x00]) + signature
        }()

        // Final cert
        let certContent = tbs + sigAlg + sigBits
        let certLen = certContent.count
        if certLen < 128 { return Data([0x30,UInt8(certLen)]) + certContent }
        if certLen < 256 { return Data([0x30,0x81,UInt8(certLen)]) + certContent }
        return Data([0x30,0x82,UInt8((certLen>>8)&0xFF),UInt8(certLen&0xFF)]) + certContent
    }
}
