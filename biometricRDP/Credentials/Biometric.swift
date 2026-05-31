import Foundation
import CryptoKit
import CommonCrypto

enum Biometric {
    /// Derive a 32-byte AES key from a test secret using PBKDF2.
    /// Used in test mode where biometrics are unavailable.
    static func deriveKeyFromTestSecret(_ secret: String) -> Data {
        guard let salt = "biometricRDP-test-salt".data(using: .utf8),
              let password = secret.data(using: .utf8) else { return Data() }
        let saltBytes = Array(salt)
        let passwordBytes = Array(password)
        var derived = [UInt8](repeating: 0, count: 32)
        CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            passwordBytes,
            passwordBytes.count,
            saltBytes,
            saltBytes.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
            100_000,
            &derived,
            32
        )
        return Data(derived)
    }
}
